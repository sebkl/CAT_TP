package cattp

import (
	"net"
	"bytes"
	"fmt"
	"time"
	"strings"
)

//Connection states
const (
	CLOSE = iota
	LISTEN = iota
	SYNRCVD = iota
	OPEN = iota
	CLOSEWAIT = iota
	SYNSENT = iota
)

//Socket parameter
const (
	CONNECTION_HANDLER = iota
	RECEIVEWINDOW_SIZE = iota
	IDENTIFICATION = iota
)

type ParameterKey int
type ParameterValue interface{}
type SocketParameters map[ParameterKey]ParameterValue

//RetransmitCount is a configurable value to specify the amount of retries 
// that will be performed until a connection is considered to be disconnected.
var RetransmitCount int = 2

var RetransmitTimeout time.Duration = 2 * time.Second
var CLOSEWAITTimeout time.Duration = 1 * time.Second

//  Handler is the callback type for incoming data (on both sides)
type Handler func (c *Connection,ps []*Header, data []byte)

// ConnectionHandler is the callback type for an incoming connection.
type ConnectionHandler func (c *Connection)

type cattpListener struct {
	server *Server
	handler Handler
	conHandler ConnectionHandler
	clients map[string]*Connection
	lport uint16
	socketParameters SocketParameters
}

// newCattpListener is an internally used function to create a new virtual 
// listener instance for a given cattp port.
func (srv *Server) newCattpListener(lport uint16, handler Handler) *cattpListener{
	return &cattpListener{
		server: srv,
		lport: lport,
		handler: handler,
		clients: make(map[string]*Connection),
		socketParameters: make(SocketParameters),
	}
}


// Server represents a listen server (UDP) that accepts client connections.
type Server struct {
	closing bool
	abort bool
	conn *net.UDPConn
	laddr *net.UDPAddr
	closewait chan error
	listeners map[uint16]*cattpListener
}

// SendWindow keeps track of which sent packets have been acknowledged or not.
// Acknowledged packets are removed from the window and others could be retransmitted.
type SendWindow  struct {
	buf map[uint16]*Header
	last uint16 /* last acknowledged */
	newest uint16
	rtcount int /* retransmit count */
}

// ReceiveWindow keeps track of the incoming sequence. Out of sequence packets 
// will be stored and only returned in the correct sequence.
type ReceiveWindow struct {
	buf []*Header
	last uint16 /* last in order */
	lastHeader *Header
}

//clientKey is an internally used function to identify connections on UDP level
//TODO: remove port, is not required anymore.
func clientKey(a *net.UDPAddr, lp uint16)  string {
	return fmt.Sprintf("%s@%d",a.String(),lp)
}


// NewSendWindow initializes a sending window.
func NewSendWindow(last uint16,size uint16) *SendWindow {
	// Size is ignored
	return &SendWindow{buf: make(map[uint16]*Header),last: last,newest: last}
}

// NewReceiveWindow initializes a new receive window.
func NewReceiveWindow(inorder uint16, size uint16) *ReceiveWindow {
	return &ReceiveWindow{buf: make([]*Header,size),last: inorder }
}

// Add adds a packet to the sent window once it was sent.
func (s *SendWindow) Add(h *Header) *sendTimeout {
	sn := h.SeqNo()
	if sn >= s.newest {
		if (sn - s.newest) > 1 && s.newest != 0 {
			Log.Printf("Warning: Skipping Seqno.")
		}
		s.newest = sn
	} else {
		Log.Printf("Warning: Sending obsolete seqno.")
	}
	s.buf[h.SeqNo()] = h
	return &sendTimeout{seqno: h.SeqNo(), c: time.After(RetransmitTimeout) }
}

// Get returns a packet from the sending window based in its
// sequence number.
func (s *SendWindow) Get(sn uint16) *Header {
	return s.buf[sn]
}

// Used returns the amount of packets that remain in the receive window.
func (s *ReceiveWindow) Used() uint16 {
	i := uint16(0)
	for ;s.buf[i] != nil;i++ { }
	return i
}

// WindowSize determines the space that is left in the receive window.
// It is used to set the window size in each sent packet.
func (s *ReceiveWindow) WindowSize() uint16 {
	return (uint16(len(s.buf)) - s.Used())
}

//Receive takes a packet and checks whether it is out of sequence. If not it will
// be sorted and an array of in-sequence-packets will be returned.
// This array is empty if no in-sequence packets are available.
func (s *ReceiveWindow) Receive(h *Header) (ret []*Header, err error){
	s.lastHeader = h
	idx := (h.SeqNo() - s.last) - 1

	if idx >= uint16(len(s.buf)) {
		return nil,fmt.Errorf("Packet '%d', last '%d' ('%d')exceeds window size '%d'.",h.SeqNo(),s.last,idx,len(s.buf))
	}

	s.buf[idx] = h

	i := int(s.Used())

	ret = make([]*Header,i)
	if i > 0 {
		copy(ret[:i],s.buf[:i])
		copy(s.buf[:],s.buf[i:])
		for ii := i; ii < len(s.buf); ii++ {
			s.buf[ii] = nil
		}
		s.last = ret[i - 1].SeqNo()
	}
	return
}

// oosSeqNo is an internally used function to determine, which packets seqnos
// have been received out of sequence.
func (s *ReceiveWindow) oosSeqNo() (ret []uint16) {
	ret = make([]uint16,0)
	for i,p := range s.buf {
		sn := uint16(i) + s.last + 1
		if p != nil {
			ret = append(ret,sn)
		}
	}
	return
}

//Ack acknowledges an incoming packet. If the packet with the acknowledged
// sequence number is in the sending window, it will be removed
func (c *SendWindow) Ack(h *Header) error{
	//TODO: Clarify how to deal with EAK.
	//acknowledge regular                          // TODO: FIX THIS 
	if _,ok :=c.buf[h.AckNo()]; !ok && (h.AckNo() > c.newest || h.AckNo() < c.last) {
		return fmt.Errorf("Unknown ack no %d to ack last was: %d",h.AckNo(),c.last)
	}

	if h.EAK() { //acknowledge out-of-sequence packets
		acks := h.ExtendedAcks()
		for _,a := range acks {
			if _,ok := c.buf[a]; ok {
				delete(c.buf,a)
			} // Ack of unknown packe will be ignored
		}
	}
	c.last = h.AckNo()
	delete(c.buf,h.AckNo())
	c.rtcount = 0 // reset rtcount
	return nil
}

// sendTimeout is an internally used function to deal with retransmit timeouts.
type sendTimeout struct {
	c <-chan time.Time
	seqno uint16
}

// Connection represents a CAT_TP connection.
type Connection struct {
	syn *Header
	identification []byte
	listener *cattpListener
	state byte
	conn *net.UDPConn
	inbuf *bytes.Buffer
	lport uint16
	rport uint16
	laddr *net.UDPAddr
	raddr *net.UDPAddr
	maxpdusize uint16
	maxsdusize uint16
	connectwait chan error
	closewait chan error
	receiveWindow *ReceiveWindow
	sendWindow *SendWindow
	handler Handler
	conHandler ConnectionHandler
	cwtimer chan(<-chan time.Time)
	rttimer chan *sendTimeout
	pkgout chan *Header // only used for manual packet sending

	// checks which one was acknowledged and removes timer from timer queue 
	pkgin chan *Header
	// Generated packets from Write call which will be stupidly forwarded to a private send method
	dataout chan []byte

	socketParameters SocketParameters
}

func (c *Connection) localIdentification() []byte {
	d := []byte{}
	if id,ok := c.socketParameters.get(IDENTIFICATION,d).([]byte); ok {
		if len(id) > MaxIdenficationLen {
			Log.Printf("Identification length truncated to %d bytes",MaxIdenficationLen)
			return id[:MaxIdenficationLen]
		}
		return id
	}
	return d
}

func (c *Connection) Identification() []byte { return c.identification }

func (c *Connection) LocalPort() uint16 { return c.lport }

func (c *Connection) RemotePort() uint16 { return c.rport }

func (c *Connection) LocalAddr() net.Addr { return c.conn.LocalAddr() }

func (c *Connection) RemoteAddr() *net.UDPAddr { return c.raddr }

// This is the initial sequence number for the sending activity. This shall be the 
// sequence number that was previously sent in the SYN PDU.
func (c *Connection) SND_INI_SEQ_NB() uint16{ return c.syn.SeqNo() }
// This is the sequence number of the next PDU that is to be sent.
func (c *Connection) SND_NXT_SEQ_NB() uint16 {
	if c.sendWindow == nil {
		return c.SND_INI_SEQ_NB() + 1
	} else {
		return c.sendWindow.newest + 1
	}
}
// This is the sequence number of the oldest unacknowledged PDU that was sent. If all sent
//PDUs were acknowledged, it is equal to the sequence number of the next PDU that is to be sent
//(SND_NXT_SEQ_NB).
func (c *Connection) SND_UNA_PDU_SEQ_NB() uint16{  return c.sendWindow.last + 1 }
//This is the largest PDU size that may be sent.
func (c *Connection) SND_PDU_SIZE_MAX() uint16 { return c.maxpdusize }
//This is the largest SDU size that may be sent.
func (c *Connection) SND_SDU_SIZE_MAX() uint16 { return c.maxsdusize }
//This is the number of PDUs that can be received, counting from SND_UNA_PDU_SEQ_NB-1. 
func (c *Connection) SND_WIN_SIZE() uint16 { return c.receiveWindow.lastHeader.WindowSize() }
// This is the initial sequence number for the sending activity. This shall be the 
// sequence number that was previously sent in the SYN PDU.
func (c *Connection) RCV_INI_SEQ_NB() uint16 { return c.syn.SeqNo() }
// This is the sequence number of the next PDU that is to be sent.
func (c *Connection) RCV_CUR_SEQ_NB() uint16 { return c.receiveWindow.last }
// This is the sequence numbers that have been received out of sequence. 
func (c *Connection) RCV_OUT_OF_SEQ_PDU_SEQ_NB() uint16 { return 0 }
//This is the largest PDU size that may be sent.
func (c *Connection) RCV_PDU_SIZE_MAX() uint16 { return c.maxpdusize }
//This is the largest SDU size that may be sent. 
func (c *Connection) RCV_SDU_SIZE_MAX() uint16 { return c.maxsdusize }
//This is the number of PDUs that can be received, counting from SND_UNA_PDU_SEQ_NB-1. 
func (c *Connection) RCV_WIN_SIZE() uint16 {
	if c.receiveWindow == nil {
		ws,ok := c.socketParameters.get(RECEIVEWINDOW_SIZE,DefaultWindowSize).(uint16);
		if !ok {
			ws = DefaultWindowSize
		}
		return ws
	} else {
		return c.receiveWindow.WindowSize()
	}
}

//StateS returns the current state of the connection in human readable form.
func (c *Connection) StateS() (ret string) {
	if c.listener == nil {
		ret = "CLT_"
	} else {
		ret = "SRV_"
	}
	switch c.state {
		case OPEN:
			ret +=  "OPEN"
		case CLOSE:
			ret +=  "CLOSE"
		case LISTEN:
			ret +=  "LISTEN"
		case SYNRCVD:
			ret +=  "SYNRCVD"
		case SYNSENT:
			ret +=  "SYNSENT"
		case CLOSEWAIT:
			ret +=  "CLOSEWAIT"
		default:
			ret += "UNKNOWN"
	}
	return
}

// send is an internally used method to perform the actual data sending over UDP.
func (c *Connection) send(p *Header) (err error) {
	var w int

	if p.SupportsEAK() {
		// Do EAK enrichment.
		// TODO: prevent to many EAKS
		 err = p.SetEAK(c.receiveWindow.oosSeqNo())
		 if err != nil {
			return
		}
	}

	Log.Printf("%s Sending %s packet to: %s",c.StateS(),p.TypeS(),c.raddr.String())
	Log.Printf(">%s",p.String())
	if c.listener != nil {
		w,err = c.conn.WriteToUDP(p.raw,c.raddr)
	} else {
		w,err = c.conn.Write(p.raw)
	}

	if p.NeedsAck() {
		//TODO: If window full, queue packet locally or block send call
		c.rttimer <- c.sendWindow.Add(p)
	}

	if w != len(p.raw) {
		//TODO: make loop here
		Log.Printf("Could not write all bytes to UDP datagram: %d/%d",w,len(p.raw))
	}
	return
}

//NewConnection creates a new empty Connection object.
func NewConnection(lport,rport uint16) (con *Connection) {
	con = &Connection{	state:CLOSE,
				connectwait: make(chan error,2),
				closewait: make(chan error,2),
				sendWindow: NewSendWindow(0,1),
				inbuf: new(bytes.Buffer),
				conn: nil,
				laddr: nil,
				raddr: nil,
				lport: lport,
				rport: rport,
				rttimer: make(chan *sendTimeout,10),
				cwtimer: make(chan(<-chan time.Time),10),
				dataout: make(chan []byte,10),
				pkgin: make(chan *Header,10),
				pkgout: make(chan *Header,10),
				socketParameters: make(SocketParameters),
			}
	return
}

func (s SocketParameters) get(key ParameterKey, d ParameterValue) ParameterValue{
	if v,ok := s[key]; ok {
		return v
	} else {
		return d
	}
}

//retransmit performs a retransmit of the given  sequence number if
// it remains in sending window.
func (con *Connection) retransmit(seqno uint16) error {
	p := con.sendWindow.Get(seqno)
	if con.sendWindow.rtcount >= RetransmitCount {
		return fmt.Errorf("Retransmit count exceeded. %d attempts",con.sendWindow.rtcount)
	}
	if p != nil {
		con.sendWindow.rtcount++
		return con.send(p)
	} // else abort connection
	return nil
}

//loop is an internally function used to multiplex events.
func (con *Connection) loop() (err error){
	cwt := make(<-chan time.Time)
	rtt := &sendTimeout{c: make(chan time.Time)}

	for ;con.state != CLOSE; {
		select {
			case b := <-con.dataout:
				//Write call, data to be sent
				err = con.write(b)
			case p,ok := <-con.pkgin:
				// Incoming packet.
				if ok && p != nil{
					err = con.processPacket(p)
				} // else channel was closed
			case p,ok := <-con.pkgout:
				// Directly injected packet using the Send call (for testing/debugging) only
				if ok && p != nil{
					err = con.send(p)
				}// else channel was closed
			case cwt = <-con.cwtimer:
				//A Closewait timer was configured
			case rtt = <-con.rttimer:
				//A retransmit timeout was configured
			case _ = <-cwt:
				//Closewait timer is up closing the connection
				err = con.closeSocket()
			case _ = <-(rtt.c):
				//Retransmit timer ran out check if packet needs to be retransmit
				err = con.retransmit(rtt.seqno)
				if err != nil {
					con.closeSocket()
				}
		}
		if err != nil {
			Log.Printf("Error: %s",err)
		}
	}

	con.connectwait <- err
	con.closewait <- err
	return
}

//packetReader block as long as the connection is open and contiuesly reads
// packets from the underlying UDP socket:
func (con *Connection) packetReader() {
	for ;con.state != CLOSE; {
		p,_,err := readPacket(con.conn)
		if err != nil && con.state != CLOSE { // connection could be closed in the meantime
			Log.Printf("Error reading packet %s in state %s",err,con.StateS())
			continue
		}
		con.pkgin <- p
	}
	Log.Printf("Client connection to %s closed.",con.raddr.String())
}

//Connect tries to connect to a remote CAT_TP server. It is not blocking.
func Connect(addr string, lport, rport uint16, id []byte, handler Handler,params ...SocketParameters) (con *Connection, err error) {
	n := "udp" /*udp4 or udp6 */
	raddr, err := net.ResolveUDPAddr(n,addr)
	if err != nil {
		return
	}
	conn,err := net.DialUDP(n, nil, raddr)
	if err != nil {
		return
	}

	con = NewConnection(lport,rport)
	con.raddr = raddr
	con.conn = conn
	con.handler = handler

	if len(params) > 0 {
		con.socketParameters = params[0]
	}

	if id == nil {
		id = []byte{}
	}

	if len(id) > MaxIdenficationLen {
		return nil,fmt.Errorf("Identification len too long: %d/%d",len(id),MaxIdenficationLen)
	}

	//Send syn
	syn := NewSYN(	0,
			lport, // TODO: allocate local port
			rport,
			con.RCV_WIN_SIZE(),
			DefaultMaxPDUSize,
			DefaultMaxSDUSize,
			id )

	con.syn= syn
	err = con.send(syn)
	con.state = SYNSENT
	go con.packetReader()
	go con.loop()
	return
}

//WaitForConnect blocks until the connection is established or the connection failed.
func (con *Connection) WaitForConnect() error {
	return <-con.connectwait
}

//WaitForClose block until the connection is in state CLOSED.
func (con *Connection) WaitForClose() error {
	return <-con.closewait
}

//ConnectWait is a convenient function for a blocking connect.
func ConnectWait(addr string, lport, rport uint16, id []byte, handler Handler, params ...SocketParameters) (con *Connection, err error) {
	con,err = Connect(addr,lport,rport,id,handler,params...)
	return con,con.WaitForConnect()
}

//closeSocket is an internally used method to actually close the underlying UDP
// socket.
func (c *Connection) closeSocket() (err error) {
	Log.Printf("Closing connection %s -> %s",c.raddr.String(),c.laddr.String())
	l := c.listener
	if l != nil {
		delete(l.clients,clientKey(c.raddr,c.lport))
	} else {
		//Only shutdown connection if we are the client.
		err  = c.conn.Close()
	}
	c.state = CLOSE
	return
}

// Close gracefully closes a CAT_TP connection.
func (c *Connection) Close() (err error) {
	switch c.state {
		case LISTEN:
			c.closeSocket()
			return
		case OPEN:
			rst := NewRST(	0,
					c.lport,c.rport,
					c.SND_NXT_SEQ_NB(),
					c.RCV_CUR_SEQ_NB(),
					0)
			err = c.send(rst)
			c.state = CLOSEWAIT
			c.cwtimer <- time.After(CLOSEWAITTimeout)
		case CLOSEWAIT:
			return fmt.Errorf("Already in CLOSEWAIT state")
		default:
			c.closeSocket()
	}
	return
}

// Close gracefully closes a listen socket.
func (s *Server) Close() (err error) {
	Log.Printf("Closing listen socket.")
	s.closing = true
	return nil
}

// Wait blocks until the listen socket is closed. This includes
// all open client connections.
func (s *Server) Wait() error{
	return <-s.closewait
}

// CloseWait is a convenience method for a blocking Close().
func (s *Server) CloseWait() error{
	err := s.Close()
	s.Wait()
	return err
}

// processPacket is an internally used method to process an incoming packet 
// based on the current state. The state changes.
func (c *Connection) processPacket(h *Header) (err error) {
	Log.Printf("%s Processing %s packet.",c.StateS(),h.TypeS())
	switch c.state {
		case CLOSE:
			Log.Printf("Ignoring packet. In CLOSED state.")
			// nothing hapens here. Only open call expected.
		case CLOSEWAIT:
			// TODO: Check what happens with packets here ? discard ?
			// After delay TO Close and free resources
		case LISTEN:
			//Only accept SYN in CLOSE state
			if h.Type() == SYN {
				sa := NewSYNACK(h,c.RCV_WIN_SIZE(),0,0,c.localIdentification())
				c.syn = sa
				err = c.send(sa)
				c.state = SYNRCVD
				c.identification = h.Identification()
				return err
			}
		case SYNSENT:
			switch h.Type() {
				case SYNACK:
					if h.AckNo() != c.SND_INI_SEQ_NB() {
						return fmt.Errorf("Incorrect AckNo in SYNACK: %d/%d",h.AckNo(),c.SND_NXT_SEQ_NB())
					}

					c.identification = h.Identification() /* Client stes remote server identification */

					c.sendWindow = NewSendWindow(
						c.SND_INI_SEQ_NB(),
						h.WindowSize()) // Allocate the sending window for server.

					c.receiveWindow = NewReceiveWindow(
						h.SeqNo(),
						c.RCV_WIN_SIZE()) // Allocate the receive Window for server.
					ack := NewACK(	h,
							c.SND_NXT_SEQ_NB(),
							c.RCV_WIN_SIZE())
					//Send ACK
					err = c.send(ack)
					// To OPEN
					c.state = OPEN
					Log.Printf("Client connection to %s established.",c.raddr.String())
					c.connectwait <- err
					return err
				case RST:
					// TO CLOSE - nothing else to be done here
					c.closeSocket()
					return
			}
		case SYNRCVD:
			switch h.Type() {
				case ACK:
					if h.AckNo() != c.SND_INI_SEQ_NB() {
						return fmt.Errorf("Incorrect AckNo in 3WHS ACK: %d/%d",h.AckNo(),c.SND_NXT_SEQ_NB())
					}

					c.sendWindow = NewSendWindow(
						c.SND_INI_SEQ_NB(),
						h.WindowSize()) // Allocate the sending window for server.

					c.receiveWindow = NewReceiveWindow(
						c.syn.AckNo(),
						c.RCV_WIN_SIZE()) // Allocate the receive Window for server.
					//no packet to be sent here.
					c.state = OPEN

					//Do the freakin incoming connection callback.
					if c.conHandler != nil {
						// Perform incoming connection callback
						c.conHandler(c)
					}
					return
				case RST:
					c.closeSocket()
					return
			}

		case OPEN:
			if h.ACK() {
				// Verify the ack field for all packets if the ACK flag is set.
				if err := c.sendWindow.Ack(h); err != nil {
					return fmt.Errorf("%s Incorrect AckNo in ACK field of type '%s': %s",c.StateS(),h.TypeS(),err)
				}
			}

			switch h.Type() {
				case RST:
					c.state = CLOSEWAIT
					c.cwtimer <- time.After(CLOSEWAITTimeout)
					return
				case ACK:
					return
				case EAK: // Have been acked by initial Ack call.
					//TODO: acknowledge each seq no.
					if !h.NUL() {
						return
					}
					// EAK is combined wirth NUL
					// Send also an ack to this package
					fallthrough
				case DATAACK,NUL:
					inc, er := c.receiveWindow.Receive(h)
					if er != nil {
						return fmt.Errorf("%s Incorrect received packet: %s",c.StateS(),er)
					}

					//oos := c.receiveWindow.oosSeqNo()
					if len(inc) > 0 {
						for _,p := range inc {
							//TODO: check if each packet has to be acked individually. or just the last
							// Only ack last if the others have already been acked
							ack := NewACK(	p,
									c.SND_NXT_SEQ_NB(),
									c.RCV_WIN_SIZE())

							err = c.send(ack)

							//TODO: check whether to fork handler routine/thread
							if p.DataLen() > 0 {
								c.handler(c,inc,p.Payload())
							}
						}
					} else {
						ack:= New(	ACK_FLAG,
								h.Version(),
								c.LocalPort(),
								c.RemotePort(),
								c.SND_NXT_SEQ_NB(),
								c.RCV_CUR_SEQ_NB(),
								c.RCV_WIN_SIZE(),
								0  )
						err = c.send(ack)
					}
					return
			}
	}
	return fmt.Errorf("Unexpected packet of type %s in state %s.",h.TypeS(),c.StateS())
}

//write is an internally used method to create and send a data packet with the
// given payload.
func (c *Connection) write(data []byte) (err error) {
	for  ;len(data) > DefaultMaxSDUSize; {
		err = c.send(NewDataACK(0,
				c.lport,
				c.rport,
				c.SND_NXT_SEQ_NB(),
				c.RCV_CUR_SEQ_NB(),
				c.receiveWindow.WindowSize(),
				data[:DefaultMaxSDUSize]) )
		data = data[DefaultMaxSDUSize:]
		if err != nil {
			return
		}
	}

	return c.send(NewDataACK(0,
			c.lport,
			c.rport,
			c.SND_NXT_SEQ_NB(),
			c.RCV_CUR_SEQ_NB(),
			c.receiveWindow.WindowSize(),
			data) )
}

// Send is an exported method to manually send individual packets. It is intended to be
// used for testing scenarios and debugging only.
func (c *Connection) Send(h *Header) (err error) {
	c.pkgout <- h
	return nil
}

//readPackets is an internally used method to parse CAT_TP packets from
// a sequence of bytes.
func (c *Connection) readPackets(b []byte) (ret []*Header,consumed int,err error) {
	rs, err := c.conn.Read(b)
	if err != nil {
		return
	}
	b = b[:rs]

	ret = make([]*Header,0)
	for h,err := NewHeader(b); err == nil; consumed += h.TotalLen() {
		ret = append(ret,h)
	}


	if consumed != rs  {
		err = fmt.Errorf("Could not consume all read bytes.")
	} else {
		err = nil
	}
	return
}

//Read reads bytes from a connection. The Buffer handler must have been used
// to make this working.
func (c *Connection) Read(b []byte) (co int, err error) {
	co, err = c.inbuf.Read(b)
	if co != 0 {
		return
	}
	return
}

// Write sends a sequence of bytes to the CAT_TP connection.
func (c *Connection) Write(b []byte) (co int, err error) {
	switch c.state {
		case CLOSE,CLOSEWAIT,LISTEN:
			return 0, fmt.Errorf("No connection initiated.")
		default:
			c.dataout <- b
	}
	return
}

// readPacket reads a single packet from the underlying UDP socket.
func readPacket(conn *net.UDPConn) (ret *Header,raddr *net.UDPAddr,err error) {
	var buf [DefaultMaxPDUSize]byte
	r,raddr,err := conn.ReadFromUDP(buf[:])
	if err != nil {
		//Log.Printf("Could not read udp packet: %s",err)
		return
	}
	ret,err = NewHeader(buf[:r])
	if err != nil {
		Log.Printf("Error: %s\n%x",err,buf)
	}
	Log.Printf("<%s",ret.String())
	return ret,raddr,err
}



//countClients returns the amount of open client connections for all ports
func (srv *Server) countClients() (ret int) {
	for _,l := range srv.listeners {
		ret += len(l.clients)
	}
	return
}

//packetReader is the server side loop to accpet new CAT_TP connections as well as
// route incoming packets to the corresponding CAT_TP connections.
func (srv *Server) packetReader() (err error) {
	//Receive packets as long as client are existing and Close call has not yet been initiated.
	for ;(!srv.closing || srv.countClients() > 0) && !srv.abort; {
		srv.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		p,raddr,err := readPacket(srv.conn)

		if err != nil {
			if !strings.HasSuffix(err.Error(),"timeout") {
				Log.Printf("Error reading packet: %s (%t,%d,%t)",err,srv.closing,srv.countClients(),srv.abort)
			}
			continue
		}

		var listener *cattpListener
		var ok bool
		var cc *Connection

		if listener,ok = srv.listeners[p.DestPort()]; !ok {
			Log.Printf("Unassigned port. No Listener found for port %d",p.DestPort())
			continue
		}

		if cc,ok = listener.clients[clientKey(raddr,p.DestPort())]; !ok {
			//Connection does not yet exist
			cc = NewConnection(listener.lport,p.SrcPort())
			cc.listener = listener
			cc.handler = listener.handler //looked up above
			cc.conHandler = listener.conHandler
			cc.raddr = raddr
			cc.laddr = srv.laddr
			cc.conn = srv.conn
			cc.state = LISTEN
			cc.lport = p.DestPort()
			cc.socketParameters = listener.socketParameters
			listener.clients[clientKey(raddr,p.DestPort())] = cc
			go func(cc *Connection) {cc.loop()}(cc) // start own routine per connection.
		}
		cc.pkgin <- p // send packet to the connection inbound queue/channel

		if err != nil {
			Log.Printf("Error: %s",err)
		}

	}
	srv.closewait <- err
	srv.conn.Close() //TODO: Verify if this makes sense here.
	Log.Printf("Listen server %s closed.",srv.laddr.String())
	return
}

//Kill closes a client connection immediately.
func (con *Connection) Kill() {
	con.closeSocket()
}

//Kill closes server connection immediately.
func (srv *Server) Kill(clients bool) {
	//TODO: fix this dirty stuff.
	srv.Close()
	srv.abort = true
	if clients {
		for _,l := range srv.listeners {
			for _,clt := range l.clients {
				clt.Kill()
			}
		}
	}
	Log.Printf("Closing UDP socket for listen server.")
	srv.conn.Close()
	//srv.clients = nil
}

// newServer initializes a new server instance.
func newServer() (srv *Server) {
	srv = new(Server)
	srv.listeners = make(map[uint16]*cattpListener)
	return srv
}

//SetListener adds another CATTP port Listener to an existing UDP server socket.
// This functon can be used to listen to multiple CATTP ports on a single UDP server socket.
func (srv *Server) SetListener(lport uint16, handler Handler, params ...SocketParameters) *Server {
	if _,exists := srv.listeners[lport]; exists {
		Log.Printf("Overwriting port listener: %d",lport)
	}

	l := srv.newCattpListener(lport,handler)

	if len(params) > 0 {
		l.socketParameters = params[0]

		for _,v := range params[1:] {
			for k,vv := range v {
				l.socketParameters[k] = vv
			}
		}

		if v,ok := l.socketParameters[CONNECTION_HANDLER].(ConnectionHandler); ok {
			l.conHandler = v
		}
	}

	srv.listeners[lport] = l
	return srv
}

//listen creates a server and sets it in LISTEN state.
func listen(as string, lport uint16, handler Handler, params []SocketParameters) (srv *Server,err error) {
	n := "udp"
	srv = newServer()

	laddr, err := net.ResolveUDPAddr(n,as)
	if err != nil {
		return
	}
	srv.laddr = laddr

	conn,err := net.ListenUDP(n,laddr)
	if err != nil || conn == nil{
		Log.Fatalf("Server socket init failed: %s",err)
		return
	}
	srv.conn = conn
	srv.SetListener(lport,handler,params...)
	srv.closewait = make(chan error,1)
	return
}

//Listen starts a CAT_TP server asynchronously.
func Listen(as string, lport uint16, handler Handler, params ...SocketParameters) (srv *Server,err error) {
	srv,err = listen(as,lport,handler,params)
	if err != nil {
		return
	}

	go srv.packetReader()
	return
}

//Listen starts a CAT_TP server synchronously. It will block until the server 
// is in state CLOSED.
func KeepListening(as string, lport uint16, handler Handler, params ...SocketParameters) (err error) {
	srv,err := listen(as,lport,handler,params)
	if err !=nil {
		return
	}

	return srv.packetReader()
}
