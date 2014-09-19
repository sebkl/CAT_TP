package cattp

import (
	"net"
	"bytes"
	"log"
	"fmt"
	"time"
)

const (
	CLOSE = iota
	LISTEN = iota
	SYNRCVD = iota
	OPEN = iota
	CLOSEWAIT = iota
	SYNSENT = iota
)

var RetransmitCount int = 2
var RetransmitTimeout time.Duration = 2 * time.Second
var CLOSEWAITTimeout time.Duration = 1 * time.Second

type Server struct {
	closing bool
	conn *net.UDPConn
	laddr *net.UDPAddr
	lport uint16
	clients map[string]*Connection
	closewait chan error
}

type SendWindow  struct {
	buf map[uint16]*Header
	last uint16 /* last acknowledged */
	newest uint16
	rtcount int /* retransmit count */
}

type ReceiveWindow struct {
	buf []*Header
	last uint16 /* last in order */
	lastHeader *Header
}

type Handler func (c *Connection,ps []*Header, data []byte)

func EchoHandler (c *Connection,ps []*Header, data []byte) {
	r,_ := c.Write(data)
	log.Printf("Echoed data: %s/%d",string(data),r)
}

func LogHandler(c *Connection,ps []*Header, data []byte) {
	log.Printf(">#%X\n",data)
}

func BufferHandler (c *Connection,ps []*Header, data []byte) {
	dl := len(data)
	var err error
	for wl := 0;err == nil && wl < dl; {
		wl, err = c.inbuf.Write(data[wl:dl])
	}
}

func clientKey(a *net.UDPAddr) string {
	return a.String()
}

func NewSendWindow(last uint16,size uint16) *SendWindow {
	// Size is ignored
	return &SendWindow{buf: make(map[uint16]*Header),last: last,newest: last}
}

func NewReceiveWindow(inorder uint16, size uint16) *ReceiveWindow {
	return &ReceiveWindow{buf: make([]*Header,size),last: inorder }
}

func (s *SendWindow) Add(h *Header) *sendTimeout {
	s.newest = h.SeqNo()
	s.buf[h.SeqNo()] = h
	return &sendTimeout{seqno: h.SeqNo(), c: time.After(RetransmitTimeout) }
}

func (s *SendWindow) Get(sn uint16) *Header {
	return s.buf[sn]
}

func (s *ReceiveWindow) Used() uint16 {
	i := uint16(0)
	for ;s.buf[i] != nil;i++ { }
	return i
}

func (s *ReceiveWindow) WindowSize() uint16 {
	return (uint16(len(s.buf)) - s.Used())
}

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
		copy(s.buf[:(len(s.buf) - i)],s.buf[(i-1):])
		for ii := i; ii < len(s.buf); ii++ {
			s.buf[ii] = nil
		}
		s.last = ret[i - 1].SeqNo()
	}
	return
}

func (c *SendWindow) Ack(h *Header) error{
	//ackknowledge regular
	if _,ok :=c.buf[h.AckNo()]; !ok && c.last != h.AckNo() {
		return fmt.Errorf("Unknown ack no %d to ack last was: %d",h.AckNo(),c.last)
	}

	if h.EAK() { //acknowledge out-of-sequence packets
		acks := h.ExtendedAcks()
		for _,a := range acks {
			if _,ok := c.buf[a]; ok {
				delete(c.buf,a)
			} else {
				return fmt.Errorf("Unknown AckNo in EACK: %d",a)
			}
		}
	}
	c.last = h.AckNo()
	delete(c.buf,h.AckNo())
	c.rtcount = 0 // reset rtcount
	return nil
}

type sendTimeout struct {
	c <-chan time.Time
	seqno uint16
}

type Connection struct {
	syn *Header
	server *Server
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
	cwtimer chan(<-chan time.Time)
	rttimer chan *sendTimeout
	pkgout chan *Header // only used for manual packet sending
	pkgin chan *Header // checks which one was acked and removes timer from timer queue 
	dataout chan []byte // Generated packets from Write call ... will be stupidly forwarded to a private send method
	//timer Queue  // ordered array or queue for retransmit timeouts, indexed by timestamp when over */
}

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
		return DefaultWindowSize
	} else {
		return c.receiveWindow.WindowSize()
	}
}

func (c *Connection) StateS() (ret string) {
	if c.server == nil {
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

func (c *Connection) send(p *Header) (err error) {
	//log.Printf("> |%s|%d > %d|%5d|%5d|dl %5d |chk %5d %s",p.FlagString(),p.SrcPort(),p.DestPort(),p.SeqNo(),p.AckNo(),p.DataLen(),p.CheckSum(),p.TypeString())

	var w int
	log.Printf("%s Sending %s packet to: %s",c.StateS(),p.TypeS(),c.raddr.String())
	log.Printf(">%s",p.String())

	if p.NeedsAck() {
		//TODO: If window full, queue packet locally or block send call
		c.rttimer <- c.sendWindow.Add(p)
	}

	if c.server != nil {
		w,err = c.conn.WriteToUDP(p.raw,c.raddr)
	} else {
		w,err = c.conn.Write(p.raw)
	}

	if w != len(p.raw) {
		//TODO: make loop here
		log.Printf("Could not write all bytes to UDP datagram: %d/%d",w,len(p.raw))
	}
	return
}

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
			}
	return
}


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
			log.Printf("Error: %s",err)
		}
	}

	con.connectwait <- err
	con.closewait <- err
	return
}

func (con *Connection) packetReader() {
	for ;con.state != CLOSE; {
		p,_,err := readPacket(con.conn)
		if err != nil && con.state != CLOSE { // connection could be closed in the meantime
			log.Printf("Error reading packet %s in state %s",err,con.StateS())
			continue
		}
		con.pkgin <- p
	}
	log.Printf("Client connection to %s closed.",con.raddr.String())
}

func Connect(addr string, lport, rport uint16, id []byte, handlers ...Handler) (con *Connection, err error) {
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
	if len(handlers) > 0 {
		con.handler = handlers[0]
	} else {
		con.handler = BufferHandler
	}

	if id == nil {
		id = []byte{}
	}

	//Send syn
	syn := NewSYN(	0,
			lport, // TODO: allocate local port
			rport,
			DefaultWindowSize,
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

func (con *Connection) WaitForConnect() error {
	return <-con.connectwait
}

func (con *Connection) WaitForClose() error {
	return <-con.closewait
}

func ConnectWait(addr string, lport, rport uint16, id []byte, handlers ...Handler) (con *Connection, err error) {
	con,err = Connect(addr,lport,rport,id,handlers...)
	return con,con.WaitForConnect()
}

func (c *Connection) closeSocket() (err error) {
	log.Printf("Closing connection %s -> %s",c.raddr.String(),c.laddr.String())
	if c.server != nil {
		delete(c.server.clients,clientKey(c.raddr))
	}
	c.state = CLOSE
	err  = c.conn.Close()
	return
}

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

func (s *Server) Close() (err error) {
	s.closing = true
	return nil
}

func (s *Server) Wait() error{
	return <-s.closewait
}

func (s *Server) CloseWait() error{
	err := s.Close()
	s.Wait()
	return err
}

func (c *Connection) processPacket(h *Header) (err error) {
	log.Printf("%s Processing %s packet.",c.StateS(),h.TypeS())
	switch c.state {
		case CLOSE:
			log.Printf("Ignoring packet. In CLOSED state.")
			// nothing hapens here. Only open call expected.
		case CLOSEWAIT:
			// TODO: Check what happens with packets here ? discard ?
			// After delay TO CLose and free resources
		case LISTEN:
			//Only accept SYN in CLOSE state
			if h.Type() == SYN {
				sa := NewSYNACK(h,c.RCV_WIN_SIZE(),0,0)
				c.syn = sa
				err = c.send(sa)
				c.state = SYNRCVD
				return err
			}
		case SYNSENT:
			switch h.Type() {
				case SYNACK:
					if h.AckNo() != c.SND_INI_SEQ_NB() {
						return fmt.Errorf("Incorrect AckNo in SYNACK: %d/%d",h.AckNo(),c.SND_NXT_SEQ_NB())
					}

					c.sendWindow = NewSendWindow(
						c.SND_INI_SEQ_NB(),
						h.WindowSize()) // Allocate the sending window for server.
					c.receiveWindow = NewReceiveWindow(
						h.SeqNo(),
						DefaultWindowSize) // Allocate the receive Window for server.

					ack := NewACK(	h,
							c.SND_NXT_SEQ_NB(),
							c.RCV_WIN_SIZE())
					//Send ACK
					err = c.send(ack)
					// To OPEN
					c.state = OPEN
					log.Printf("Client connection to %s established.",c.raddr.String())
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
						DefaultWindowSize) // Allocate the receive Window for server.
					//no packet to be sent here.
					c.state = OPEN
					return
				case RST:
					c.closeSocket()
					return
			}

		case OPEN:
			if h.ACK() {
				// Verify the ack field for all packets if the ACK flag is set.
				if err := c.sendWindow.Ack(h); err != nil {
					return fmt.Errorf("Incorrect AckNo in ACK field of type '%s': %s",h.TypeS(),err)
				}
			}

			switch h.Type() {
				case RST:
					c.state = CLOSEWAIT
					c.cwtimer <- time.After(CLOSEWAITTimeout)
					return
				case ACK:
					return
				case DATAACK:
					inc, er := c.receiveWindow.Receive(h)
					if er != nil {
						return fmt.Errorf("Incorrect received packet: %s",er)
					}

					for _,p := range inc {
						//TODO: check if each packet has to be acked individually. or just the last
						ack := NewACK(	p,
								c.SND_NXT_SEQ_NB(),
								c.RCV_WIN_SIZE())

						err = c.send(ack)
					}

					//TODO: check whether to fork handler routine/thread
					c.handler(c,inc,h.Payload())
					return
				case EAK: // Have been acked by initial Ack call.
					//TODO: ACkknowledge each seq no.
					if !h.NUL() {
						break
					}
					// EAK is combined wirth NUL
					// Send also an ack to this package
					fallthrough
				case NUL:
					//This is just a keep alive.
					ack := NewACK(	h,
							c.SND_NXT_SEQ_NB(),
							c.RCV_WIN_SIZE())
					err = c.send(ack)
					return
			}
	}
	return fmt.Errorf("Unexpected packet of type %s in state %s.",h.TypeS(),c.StateS())
}

func (c *Connection) write(data []byte) error {
	//TODO: split up packages if length od data exceeds max PDU/SDU (fragmentation)
	return c.send(NewDataACK(	0,
				c.lport,
				c.rport,
				c.SND_NXT_SEQ_NB(),
				c.RCV_CUR_SEQ_NB(),
				DefaultWindowSize,
				data) )
}


// Send is an exported method to manualy send individual packets. It is intentded to be
// used for testing scenarios and debugging only.
func (c *Connection) Send(h *Header) (err error) {
	c.pkgout <- h
	return nil
}

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

func (c *Connection) Read(b []byte) (co int, err error) {
	co, err = c.inbuf.Read(b)
	if co != 0 {
		return
	}
	return
}

func (c *Connection) Write(b []byte) (co int, err error) {
	switch c.state {
		case CLOSE,CLOSEWAIT,LISTEN:
			return 0, fmt.Errorf("No connection initiated.")
		default:
			c.dataout <- b
	}
	return
}

func readPacket(conn *net.UDPConn) (ret *Header,raddr *net.UDPAddr,err error) {
	var buf [DefaultMaxPDUSize]byte
	r,raddr,err := conn.ReadFromUDP(buf[:])
	if err != nil {
		return
	}
	ret,err = NewHeader(buf[:r])
	if err != nil {
		log.Printf("Error: %s\n%x",err,buf)
	}
	log.Printf("<%s",ret.String())
	return ret,raddr,err
}

func (srv *Server) packetReader(handler Handler) (err error) {
	//Receive packets as long as client are existing and Close call has not yet been initiated.
	srv.closewait = make(chan error,1)
	for ;!srv.closing || len(srv.clients) > 0; {
		p,raddr,err := readPacket(srv.conn)
		if err != nil {
			continue
		}

		var cc *Connection
		var ok bool
		if cc,ok = srv.clients[clientKey(raddr)]; !ok {
			//Connection does not yet exist
			cc = NewConnection(srv.lport,p.SrcPort())
			cc.server = srv
			cc.handler = handler
			cc.raddr = raddr
			cc.laddr = srv.laddr
			cc.conn = srv.conn
			cc.state = LISTEN
			srv.clients[clientKey(raddr)] = cc
			go func(cc *Connection) {cc.loop()}(cc) // start own routine per connection.
		}
		cc.pkgin <- p // send packet to the connection inbound queue/channel

		if err != nil {
			log.Printf("Error: %s",err)
		}

	}
	log.Printf("Listen server %s closed.",srv.laddr.String())
	srv.closewait <- err
	return
}

func listen(as string, lport uint16, handler Handler) (srv *Server,err error) {
	n := "udp"
	srv = new(Server)

	laddr, err := net.ResolveUDPAddr(n,as)
	if err != nil {
		return
	}
	srv.laddr = laddr

	conn,err := net.ListenUDP(n,laddr)
	if err != nil {
		return
	}
	srv.conn = conn
	srv.lport = lport
	srv.clients = make(map[string]*Connection)
	return
}

func Listen(as string, lport uint16, handler Handler) (srv *Server,err error) {
	srv,err = listen(as,lport,handler)
	go srv.packetReader(handler)
	return
}

func KeepListening(as string, lport uint16, handler Handler) (err error) {
	srv,err := listen(as,lport,handler)
	if err !=nil {
		return
	}
	return srv.packetReader(handler)
}
