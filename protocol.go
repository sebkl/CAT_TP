package cattp
//Package cattp implements CAT_TP packet decoding for pcap streams. 
//It is supposed to support both, cleint and server side implementations as well in the future.

import(
	"fmt"
	"crypto/md5"
	"encoding/base64"
)

type Header struct {
	raw []byte
	hdr [18]byte
	synpduhdr [5]byte
	identification []byte
	rstpduhdr byte
	payload []byte
}

const (
	UNK	= 0
	SYN	= 1
	SYNACK	= 2
	ACK	= 3
	RST	= 4
	FLAG_MASK = 0xFC
	SYN_FLAG = 0x80
	ACK_FLAG = 0x40
	EAK_FLAG = 0x20
	RST_FLAG = 0x10
	NUL_FLAG = 0x08
	SEG_FLAG = 0x04
)

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
		default:
			return UNK
	}
}
func (p *Header) Version() int { return int(p.hdr[0] & 0x03) }

func (p *Header) HeaderLen() int { return int(p.hdr[3]) }

func (p *Header) SrcPort() int { return (int(p.hdr[4]) << 8) | int(p.hdr[5]) }

func (p *Header) DestPort() int { return (int(p.hdr[6]) << 8) | int(p.hdr[7]) }

func (p *Header) DataLen() int { return (int(p.hdr[8]) << 8) | int(p.hdr[9]) }

func (p *Header) SeqNo() int { return (int(p.hdr[10]) << 8) | int(p.hdr[11]) }

func (p *Header) AckNo() int { return (int(p.hdr[12]) << 8) | int(p.hdr[13]) }

func (p *Header) CheckSum() int { return (int(p.hdr[16]) << 8) | int(p.hdr[17]) }

func (p *Header) MaxPDUSize() int { return (int(p.synpduhdr[0]) << 8) | int(p.synpduhdr[1]) }

func (p *Header) MaxSDUSize() int { return (int(p.synpduhdr[2]) << 8) | int(p.synpduhdr[3]) }

func (p *Header) IdentificationLen() int { return int(p.synpduhdr[4]) }

func (p *Header) Identification() []byte { return p.identification }

func (p *Header) ReasonCode() byte { return p.rstpduhdr }

func (p *Header) Payload() []byte { return p.payload }

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
		case SYN:
			return fmt.Sprintf("|il %3d",p.IdentificationLen())
		case RST:
			return fmt.Sprintf("|rc %2d|%s",int(p.ReasonCode()),p.ReasonString())
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
	ret = &Header{raw: raw}

	if len(raw) < len(ret.hdr) {
		return nil, fmt.Errorf("No cattp header. %d/%d",len(raw),18)
	}

	c := 0 // Amount of consumed header bytes
	for ;c<len(ret.hdr);c++ {
		ret.hdr[c] = raw[c]
	}

	switch ret.Type() {
		case SYN:
			//parse additional header for SYN PDU
			for i:=0; i < len(ret.synpduhdr); {
				ret.synpduhdr[i] = raw[c]
				i++
				c++
			}
			//parse variable Identification field.
			ret.identification = raw[c:c+int(ret.synpduhdr[4])]
			c+=int(ret.synpduhdr[4])
		case RST:
			//just take the reason code here
			ret.rstpduhdr = raw[c]
			c++
		default:
			//TODO: comment in once all other types have been implemented.
			//log.Printf("E|Unknown pdu type: %d",ret.Type())

	}

	ret.payload = raw[c:]
	return
}

