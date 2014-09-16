package cattp

import (
	"net"
	"bytes"
	"log"
	"fmt"
)

const (
	CLOSE = iota
	LISTEN = iota
	SYNRCVD = iota
	OPEN = iota
	CLOSEWAIT = iota
	SYNSENT = iota
)

type Server struct {
	closing bool
	conn *net.UDPConn
	laddr *net.UDPAddr
	lport uint16
	clients map[string]*Connection
}

type SendWindow  struct {
	buf map[uint16]*Header
	last uint16 /* last acknowledged */
	newest uint16
}

type ReceiveWindow struct {
	buf []*Header
	last uint16 /* last in order */
	lastHeader *Header
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

func (s *SendWindow) Add(h *Header) {
	s.newest = h.SeqNo()
	s.buf[h.SeqNo()] = h
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
	return nil
}

type Connection struct {
	syn *Header
	server *Server
	state byte
	conn *net.UDPConn
	inbuf *bytes.Buffer
	outbuf *bytes.Buffer
	lport uint16
	rport uint16
	laddr *net.UDPAddr
	raddr *net.UDPAddr
	maxpdusize uint16
	maxsdusize uint16
	receiveWindow *ReceiveWindow
	sendWindow *SendWindow
	handler Handler
}

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


type Handler func (c *Connection, data []byte)
func LogHandler(c *Connection, data []byte) {
	log.Printf("> %X\n",data)
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

	if p.Type() == DATAACK {
		//TODO: If window full, queue packet locally or block send call
		c.sendWindow.Add(p)
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
				inbuf: new(bytes.Buffer),
				outbuf: new(bytes.Buffer),
				conn: nil,
				laddr: nil,
				raddr: nil,
				lport: lport,
				rport: rport,
			}
	return
}

func Connect(addr string, lport, rport uint16, ids ...[]byte) (con *Connection, err error) {
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

	id := make([]byte,0)
	if len(ids) > 0 {
		id = ids[0]
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
	for con.state = SYNSENT;con.state != OPEN; {
		p,_,err := readPacket(con.conn)
		if err == nil {
			err = con.processPacket(p)
			if err != nil {
				log.Printf("Error: %s",err)
			}

		}
	}
	log.Printf("Client connection to %s established.",con.raddr.String())
	return
}

func (con *Connection) Loop(handler Handler) (err error){
	con.handler = handler
	for ;con.state != CLOSE; {
		p,_,err := readPacket(con.conn)
		if err != nil {
			continue
		}

		err = con.processPacket(p)
		if err != nil {
			log.Printf("Error: %s",err)
		}
	}
	log.Printf("Client connection to %s closed.",con.raddr.String())
	return
}

func (c *Connection) closeSocket() (err error) {
	log.Printf("Closing connection %s -> %s",c.raddr.String(),c.laddr.String())
	if c.server != nil {
		delete(c.server.clients,clientKey(c.raddr))
	}
	err  = c.conn.Close()
	c.state = CLOSE
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
			//TODO: setup timer
			c.closeSocket()
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
					//TODO: setup timer
					c.closeSocket()
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

					// take data
					err = c.readPayload(h)
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
			}
	}
	return fmt.Errorf("Unexpected packet of type %s in state %s.",h.TypeS(),c.StateS())
}

func (c *Connection) write() (err error) {
	ds := uint16(c.outbuf.Len())
	if ds <= 0{
		return
	}

	mds := (c.SND_PDU_SIZE_MAX() - BASE_HLEN)

	if ds > mds {
		ds = mds
	}

	mb := make([]byte,ds)

	rs, err := c.outbuf.Read(mb)
	if err != nil {
		return
	}

	p := NewDataACK(	0,
				c.lport,
				c.rport,
				c.SND_NXT_SEQ_NB(),
				c.RCV_CUR_SEQ_NB(),
				DefaultWindowSize,
				mb[:rs])
	return c.send(p)
}

func (c *Connection) readPayload(p *Header) (err error) {
	dl := int(p.DataLen())
	for wl := 0;err == nil && wl < dl; {
		wl, err = c.inbuf.Write(p.Payload()[wl:dl])
	}

	if c.handler != nil {
		var buf [DefaultMaxPDUSize]byte
		for rl := 1; rl > 0 && err == nil; {
			rl, err = c.inbuf.Read(buf[:])
			if rl > 0 {
				c.handler(c,buf[:rl])
			}
		}
		err = nil
	}

	return
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
			co, err = c.outbuf.Write(b)
			err = c.write()
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
	log.Printf("%s",ret.String())
	return ret,raddr,err
}

func Listen(as string, lport uint16) (srv *Server, err error) {
	n := "udp"
	srv = new(Server)

	laddr, err := net.ResolveUDPAddr(n,as)
	if err != nil {
		return
	}
	srv.laddr = laddr

	conn,err := net.ListenUDP(n,laddr)
	srv.conn = conn
	srv.lport = lport
	srv.clients = make(map[string]*Connection)
	return
}

func (srv *Server) Loop(handler Handler) (err error) {
	//Receive packets as long as client are existing and Close call has not yet been initiated.
	for ;!srv.closing || len(srv.clients) > 0; {
		p,raddr,err := readPacket(srv.conn)
		if err != nil {
			continue
		}
		if cc,ok := srv.clients[clientKey(raddr)]; !ok {
			//Connection does not yet exist
			cc = NewConnection(srv.lport,p.SrcPort())
			cc.server = srv
			cc.handler = handler
			cc.raddr = raddr
			cc.laddr = srv.laddr
			cc.conn = srv.conn
			cc.state = LISTEN
			srv.clients[clientKey(raddr)] = cc
			err = cc.processPacket(p)
		} else {
			err = cc.processPacket(p)
		}

		if err != nil {
			log.Printf("Error: %s",err)
		}

	}
	log.Printf("Listen server %s closed.",srv.laddr.String())
	return
}
