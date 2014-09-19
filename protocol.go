package cattp
//Package cattp implements CAT_TP packet decoding for pcap streams. 
//It is supposed to support both, cleint and server side implementations as well in the future.

import(
	"math/rand"
	"fmt"
	"crypto/md5"
	"encoding/base64"
	"strings"
	"strconv"
)


const ( // PDU TYPES
	UNK	= iota
	SYN	= iota
	SYNACK	= iota
	ACK	= iota
	RST	= iota
	DATAACK = iota
	NUL	= iota
	EAK	= iota
)


const ( // PDU Flags
	FLAG_MASK = 0xFC
	SYN_FLAG = 0x80
	ACK_FLAG = 0x40
	EAK_FLAG = 0x20
	RST_FLAG = 0x10
	NUL_FLAG = 0x08
	SEG_FLAG = 0x04
)

const ( // Header Constants
	BASE_HLEN = 18
	SYN_HLEN = 5
)

const ( // Default Values
	DefaultMaxPDUSize = 1024
	DefaultMaxSDUSize = 3276
	DefaultSrcPort = 1
	DefaultDestPort = 9000
	DefaultWindowSize = 10
)

type Header struct {
	raw []byte
	hdr [18]byte
	synpduhdr [SYN_HLEN]byte
	identification []byte
	rstpduhdr byte
	ackpduhdr [2]byte
	eakpduhdr []byte
	payload []byte
}

func NewSeqNo() uint16 {
	return uint16(rand.Intn(0xffff))
}

func (p *Header) NeedsAck() bool { t:= p.Type(); return t== DATAACK || t == NUL || t == SYN }

func (p *Header) SYN() bool { return (p.hdr[0] & SYN_FLAG) > 0 }

func (p *Header) ACK() bool { return (p.hdr[0] & ACK_FLAG) > 0 }

func (p *Header) EAK() bool { return (p.hdr[0] & EAK_FLAG) > 0 }

func (p *Header) RST() bool { return (p.hdr[0] & RST_FLAG) > 0 }

func (p *Header) NUL() bool { return (p.hdr[0] & NUL_FLAG) > 0 }

func (p *Header) SEG() bool { return (p.hdr[0] & SEG_FLAG) > 0 }

func (p *Header) Type() int {
	switch p.hdr[0] & FLAG_MASK {
		case SYN_FLAG, SYN_FLAG | SEG_FLAG:
			return SYN
		case RST_FLAG, RST_FLAG | ACK_FLAG:
			return RST
		case SYN_FLAG | ACK_FLAG:
			return SYNACK
		case EAK_FLAG | ACK_FLAG,EAK_FLAG | ACK_FLAG | SEG_FLAG:
			return EAK
		case NUL_FLAG | ACK_FLAG:
			return NUL
		case ACK_FLAG:
			if p.DataLen() > 0 {
				return DATAACK
			} else {
				return ACK
			}
		default:
			return UNK
	}
}

func (p *Header) TypeS() (ret string) {
	switch p.Type() {
		case SYN:
			ret = "SYN"
		case SYNACK:
			ret = "SYNACK"
		case ACK:
			ret = "ACK"
		case DATAACK:
			ret = "DATAACK"
		case RST:
			ret = "RST"
		case NUL:
			ret = "NUL"
		case EAK:
			ret = "EAK"
		default:
			ret = "UNK"
	}
	return
}

func (p *Header) Version() byte { return byte(p.hdr[0] & 0x03) }

func (p *Header) HeaderLen() byte { return byte(p.hdr[3]) }

func (p *Header) SrcPort() uint16 { return (uint16(p.hdr[4]) << 8) | uint16(p.hdr[5]) }

func (p *Header) DestPort() uint16 { return (uint16(p.hdr[6]) << 8) | uint16(p.hdr[7]) }

func (p *Header) DataLen() uint16 { return (uint16(p.hdr[8]) << 8) | uint16(p.hdr[9]) }

func (p *Header) TotalLen() int { return len(p.raw) }

func (p *Header) SeqNo() uint16 { return (uint16(p.hdr[10]) << 8) | uint16(p.hdr[11]) }

func (p *Header) AckNo() uint16 { return (uint16(p.hdr[12]) << 8) | uint16(p.hdr[13]) }

func (p *Header) WindowSize() uint16 { return (uint16(p.hdr[14]) << 8) | uint16(p.hdr[15]) }

func (p *Header) CheckSum() uint16 { return (uint16(p.hdr[16]) << 8) | uint16(p.hdr[17]) }

func (p *Header) MaxPDUSize() uint16 { return (uint16(p.synpduhdr[0]) << 8) | uint16(p.synpduhdr[1]) }

func (p *Header) MaxSDUSize() uint16 { return (uint16(p.synpduhdr[2]) << 8) | uint16(p.synpduhdr[3]) }

func (p *Header) IdentificationLen() byte { return byte(p.synpduhdr[4]) }

func (p *Header) Identification() []byte { return p.identification }

func (p *Header) ReasonCode() byte { return p.rstpduhdr }

func (p *Header) Payload() []byte { return p.payload }

func (p *Header) ExtendedAcks() []uint16 {
	ret := make([]uint16,int(len(p.eakpduhdr) / 2))
	for i,_ := range ret {
		idx := i * 2
		ret[i] = (uint16(p.eakpduhdr[idx]) << 8) | uint16(p.eakpduhdr[idx+1])
	}
	return ret
}

// ReasonString returns a human readable message for the reason code of the RST packet.
func (p *Header) ReasonString() string {
	switch p.ReasonCode() {
		case 0: return "Normal ending;"
		case 1: return "Connection set-up failed, illegal parameters;"
		case 2: return "Temporarily unable to set up this connection;"
		case 3: return "Requested Port not available;"
		case 4: return "Unexpected PDU received;"
		case 5: return "Maximum retries exceeded;"
		case 6: return "Version not supported;"
		default: return fmt.Sprintf("NOT_YET_IMPLEMENTED ReasonCode: %d",int(p.ReasonCode()))
	}
}

func (p *Header) FlagString() string {
	syn := "..."
	ack := "..."
	rst := "..."
	nul := "..."
	seg := "..."
	eak := "..."
	if p.SYN() {
		syn = "SYN"
	}
	if p.ACK() {
		ack = "ACK"
	}
	if p.RST() {
		rst = "RST"
	}
	if p.EAK() {
		eak = "EAK"
	}
	if p.NUL() {
		nul = "NUL"
	}
	if p.SEG() {
		seg = "SEG"
	}

	return syn + ack + eak + rst + nul + seg
}

func (p *Header) TypeString() string {
	switch p.Type() {
		case SYN,SYNACK:
			return fmt.Sprintf("|il %3d",p.IdentificationLen())
		case RST:
			return fmt.Sprintf("|rc %2d|%s",int(p.ReasonCode()),p.ReasonString())
		case EAK:
			acks := p.ExtendedAcks()
			sacks := make([]string,len(acks))
			for i,a := range acks { sacks[i] = strconv.Itoa(int(a)) }
			return fmt.Sprintf("|acks %s", strings.Join(sacks,","))
		default:
			return fmt.Sprintf("|-")
	}
}

// HashString returns a hash over the entire cattp packet (udp payload)
func (p *Header) HashString() string {
	bhash := md5.Sum(p.raw)
	nhash:= make ([]byte,len(bhash))
	for i,b := range bhash {
		nhash[i] = b
	}
	return base64.StdEncoding.EncodeToString(nhash)
}

func (p *Header) BinaryString(mc ...int) string {
	ret := OctetDumper.Dump(p.raw)
	if len(mc) > 0 && len(ret) > mc[0] {
		by := []byte(ret)
		return string(by[:mc[0]])
	}
	return ret
}

// NewHeader creates a new cattp packet based on an existing pcap packet. Error is returned if
// the pcap packet is not a cattp packet.
func NewHeader(raw []byte) (ret *Header,err error) {
	ret = &Header{raw: raw, eakpduhdr: make([]byte,0)}

	if len(raw) < len(ret.hdr) {
		return nil, fmt.Errorf("No cattp header. %d/%d",len(raw),BASE_HLEN)
	}

	c := 0 // Amount of consumed header bytes
	for ;c<len(ret.hdr);c++ {
		ret.hdr[c] = raw[c]
	}

	switch ret.Type() {
		case SYN,SYNACK: //TODO: Asuming SYNACK has same pdu as SYN
			//parse additional header for SYN PDU
			for i:=0; i < len(ret.synpduhdr); {
				ret.synpduhdr[i] = raw[c]
				i++
				c++
			}
			//parse variable Identification field.
			ret.identification = raw[c:c+int(ret.synpduhdr[4])]
			c+=int(ret.synpduhdr[4])
		case ACK:
			//Payload is just taken based on DataLen field.
		case RST:
			//just take the reason code here
			ret.rstpduhdr = raw[c]
			c++
		case NUL:
			// No Payload except for eack which is covered above.
		case EAK:
			toack := int(ret.HeaderLen()) - len(ret.hdr)
			if toack % 2 != 0 || toack < 2{
				return nil,fmt.Errorf("Invalid EAK header (%d byte eak header)", toack)
			}
			ret.eakpduhdr = raw[c:(c+toack)]
			c+=toack
			//TODO: deal with data
		default:
			//TODO: comment in once all other types have been implemented.
			//log.Printf("E|Unknown pdu type: %d",ret.Type())

	}
	if c != int(ret.HeaderLen()) {
		err = fmt.Errorf("HeaderLen does not match %d/%d",c,ret.HeaderLen())
		return
	}

	end := c + int(ret.DataLen())
	ret.payload = raw[c:end]

	// Check checksum
	if ret.CheckSum() != ret.computeCheckSum() {
		err = fmt.Errorf("Checksum incorrect: %d/%d",ret.computeCheckSum(),ret.CheckSum())
	}
	return
}

func (p *Header) computeCheckSum() uint16 {
	var sum uint32
	var i uint
	var l uint = uint(len(p.raw))
	for i =0; i < l; i++ {
		sum += uint32(p.raw[i]) << (8 * ((i+1)%2))
	}
	sum -= uint32(p.CheckSum())
	fold := uint16((sum & 0xffff0000) >> 16)
	sum+=uint32(fold)

	return uint16(^sum)
}

func (p *Header) setShort(idx byte,d uint16) {
	p.raw[idx] = byte((d & 0xff00) >> 8)
	p.raw[idx + 1] = byte(d & 0x00ff)
	p.hdr[idx] = p.raw[idx]
	p.hdr[idx + 1] = p.raw[idx + 1]
}

func (p *Header) setFlags(flags byte, version byte) {
	p.raw[0] = flags | version
	p.hdr[0] = p.raw[0]
}

func (p *Header) setHeaderLen(l byte) { p.raw[3] = l; p.hdr[3] = l }

func (p *Header) setRFU(rfu uint16) { p.setShort(1,rfu) }

func (p *Header) setSrcPort(port uint16) { p.setShort(4,port) }

func (p *Header) setDestPort(port uint16) { p.setShort(6,port) }

func (p *Header) setDataLen(l uint16) { p.setShort(8,l) }

func (p *Header) setSeqNo(no uint16) { p.setShort(10,no) }

func (p *Header) setAckNo(no uint16) { p.setShort(12,no) }

func (p *Header) setWindowSize(size uint16) { p.setShort(14,size) }

func (p *Header) setCheckSum(sum uint16) { p.setShort(16,sum) }

func (p *Header) setReasonCode(c byte) { p.rstpduhdr = c }

func (p *Header) setData(d []byte) {
	p.payload = make([]byte,len(d))
	for i:=0;i < len(d);i++ {
		p.payload[i] = d[i]
		p.raw[BASE_HLEN + i] = d[i]
	}
	p.setDataLen(uint16(len(d)))
}

func (p *Header) setMaxPDUSize(size uint16) {
	p.synpduhdr[0] = byte( ( size & 0xff00) >> 8 )
	p.synpduhdr[1] = byte( size & 0x00ff)
	p.raw[BASE_HLEN] = p.synpduhdr[0]
	p.raw[BASE_HLEN + 1] = p.synpduhdr[1]
}

func (p *Header) setMaxSDUSize(size uint16) {
	p.synpduhdr[2] = byte( ( size & 0xff00) >> 8 )
	p.synpduhdr[3] = byte( size & 0x00ff)
	p.raw[BASE_HLEN + 2] = p.synpduhdr[2]
	p.raw[BASE_HLEN + 3] = p.synpduhdr[3]
}

func (p *Header) setIdentification(d []byte) {
	l := len(d)
	p.identification = make([]byte,l)
	p.synpduhdr[4] = byte(l)
	p.raw[BASE_HLEN + 4] = byte(l)
	for i:=0;i < l;i++ {
		p.raw[BASE_HLEN + SYN_HLEN + i] = d[i]
		p.identification[i] = d[i]
	}
}

func (p *Header) UpdateCheckSum() { p.setCheckSum(p.computeCheckSum()) }

func (p *Header) String() string {
	return fmt.Sprintf(	"|%s|%d > %d|seq %5d|ack %5d|ws %5d |hl %3d |dl %5d |chk %5d %s",
				p.FlagString(),
				p.SrcPort(),
				p.DestPort(),
				p.SeqNo(),
				p.AckNo(),
				p.WindowSize(),
				p.HeaderLen(),
				p.DataLen(),
				p.CheckSum(),
				p.TypeString(),
			)
}

func (p *Header) Raw() []byte { return p.raw }

func New(flags, version byte,srcport, destport,seq,ack, wsize, datlen uint16) (ret *Header){
	ret = &Header{}
	ret.raw = make([]byte,BASE_HLEN + datlen)
	ret.setFlags(flags,version)
	ret.setRFU(0) //RFU not yet used
	ret.setSrcPort(srcport)
	ret.setDestPort(destport)
	ret.setSeqNo(seq)
	ret.setAckNo(ack)
	ret.setWindowSize(wsize)
	ret.setHeaderLen(BASE_HLEN)
	ret.UpdateCheckSum()
	return
}

func NewNUL(version byte,srcport, destport,seq,ack, wsize uint16) *Header{
	return New(	NUL_FLAG | ACK_FLAG,
			version,
			srcport,
			destport,
			seq,
			ack,
			wsize,
			0)
}

func NewRST(version byte, srcport, destport,seq,ack uint16, rc byte) (ret *Header) {
	ret = New(	RST_FLAG,
			version,
			srcport,
			destport,
			seq,
			ack,
			0,
			1  )

	ret.setReasonCode(0)
	ret.setHeaderLen(BASE_HLEN + 1)
	ret.UpdateCheckSum()
	return
}

func NewSYN(version byte,srcport, destport, wsize, maxpdusize, maxsdusize uint16, identification []byte) (ret *Header) {
	al := uint16(SYN_HLEN + len(identification))

	ret = New(	SYN_FLAG,
			0,
			srcport,
			destport,
			NewSeqNo(),
			0,
			wsize,
			al  )

	ret.setMaxPDUSize(maxpdusize)
	ret.setMaxSDUSize(maxsdusize)
	ret.setIdentification(identification)
	ret.setHeaderLen(byte(BASE_HLEN + 4 + 1 + len(identification)))
	ret.UpdateCheckSum()
	return
}

func NewSYNACK(syn *Header, wsize,maxpdusize, maxsdusize uint16) (ret *Header) {
	identification := make([]byte,0) //TODO: check when to use identification
	ret = NewSYN(	0,
			syn.DestPort(),
			syn.SrcPort(),
			wsize,
			maxsdusize,
			maxsdusize,
			identification )

	ret.setFlags(SYN_FLAG | ACK_FLAG, syn.Version())
	ret.setAckNo(syn.SeqNo())
	ret.UpdateCheckSum()
	return
}

func NewACK(p *Header, seqno, wsize uint16) *Header {
	return New(	ACK_FLAG,
			p.Version(),
			p.DestPort(),
			p.SrcPort(),
			seqno,
			p.SeqNo(),
			wsize,
			0  )
}


func NewDataACK(version byte, srcport,destport,seqno,ackno,wsize uint16, data []byte) (ret *Header) {
	ret = New(ACK_FLAG,version,srcport,destport,seqno,ackno,wsize,uint16(len(data)))
	ret.setData(data)
	ret.UpdateCheckSum()
	return
}

