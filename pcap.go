package cattp
//Package cattp implements CAT_TP packet decoding for pcap streams. 
//It is supposed to support both, cleint and server side implementations as well in the future.

import(
	"github.com/miekg/pcap"
	"fmt"
	"crypto/md5"
	"encoding/base64"
)

type CATTPPacket struct {
	ip *pcap.Iphdr
	udp *pcap.Udphdr
	hdr [18]byte
	synpduhdr [5]byte
	identification []byte
	rstpduhdr byte
	raw []byte
	payload []byte
}

type Dumper interface {
	Dump(data []byte) string
}

type HexDumper struct {}
func (h HexDumper) Dump(data []byte) string {
	return fmt.Sprintf("%X",data)
}
var OctetDumper Dumper = HexDumper{}

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

func (p *CATTPPacket) SYN() bool { return (p.hdr[0] & SYN_FLAG) > 0 }

func (p *CATTPPacket) ACK() bool { return (p.hdr[0] & ACK_FLAG) > 0 }

func (p *CATTPPacket) EAK() bool { return (p.hdr[0] & EAK_FLAG) > 0 }

func (p *CATTPPacket) RST() bool { return (p.hdr[0] & RST_FLAG) > 0 }

func (p *CATTPPacket) NUL() bool { return (p.hdr[0] & NUL_FLAG) > 0 }

func (p *CATTPPacket) SEG() bool { return (p.hdr[0] & SEG_FLAG) > 0 }

func (p *CATTPPacket) Type() int {
	switch p.hdr[0] & FLAG_MASK {
		case SYN_FLAG, SYN_FLAG | SEG_FLAG:
			return SYN
		case RST_FLAG, RST_FLAG | ACK_FLAG:
			return RST
		default:
			return UNK
	}
}
func (p *CATTPPacket) Version() int { return int(p.hdr[0] & 0x03) }

func (p *CATTPPacket) HeaderLen() int { return int(p.hdr[3]) }

func (p *CATTPPacket) SrcPort() int { return (int(p.hdr[4]) << 8) | int(p.hdr[5]) }

func (p *CATTPPacket) DestPort() int { return (int(p.hdr[6]) << 8) | int(p.hdr[7]) }

func (p *CATTPPacket) DataLen() int { return (int(p.hdr[8]) << 8) | int(p.hdr[9]) }

func (p *CATTPPacket) SeqNo() int { return (int(p.hdr[10]) << 8) | int(p.hdr[11]) }

func (p *CATTPPacket) AckNo() int { return (int(p.hdr[12]) << 8) | int(p.hdr[13]) }

func (p *CATTPPacket) CheckSum() int { return (int(p.hdr[16]) << 8) | int(p.hdr[17]) }

func (p *CATTPPacket) MaxPDUSize() int { return (int(p.synpduhdr[0]) << 8) | int(p.synpduhdr[1]) }

func (p *CATTPPacket) MaxSDUSize() int { return (int(p.synpduhdr[2]) << 8) | int(p.synpduhdr[3]) }

func (p *CATTPPacket) IdentificationLen() int { return int(p.synpduhdr[4]) }

func (p *CATTPPacket) Identification() []byte { return p.identification }

func (p *CATTPPacket) ReasonCode() byte { return p.rstpduhdr }

func (p *CATTPPacket) Payload() []byte { return p.payload }

func (p *CATTPPacket) ReasonString() string {
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

func (p *CATTPPacket) FlagString() string {
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

func (p *CATTPPacket) TypeString() string {
	switch p.Type() {
		case SYN:
			return fmt.Sprintf("|il %3d|%s",p.IdentificationLen(),OctetDumper.Dump(p.Identification()))
		case RST:
			return fmt.Sprintf("|rc %2d|%s",int(p.ReasonCode()),p.ReasonString())
		default:
			return fmt.Sprintf("|-")
	}
}

func (p *CATTPPacket) HashString() string {
	bhash := md5.Sum(p.raw)
	nhash:= make ([]byte,len(bhash))
	for i,b := range bhash {
		nhash[i] = b
	}
	return base64.StdEncoding.EncodeToString(nhash)
}

func (p *CATTPPacket) String() string{
	return fmt.Sprintf("|%15s:%5d > %15s:%5d|%s v%d |hl %d |p %d > %d |dl %5d |sq %5d |ac %5d |ck %5d |pl %5d %s",
		p.ip.SrcAddr(),
		p.udp.SrcPort,
		p.ip.DestAddr(),
		p.udp.DestPort,
		p.FlagString(),
		p.Version(),
		p.HeaderLen(),
		p.SrcPort(),
		p.DestPort(),
		p.DataLen(),
		p.SeqNo(),
		p.AckNo(),
		p.CheckSum(),
		len(p.Payload()),
		p.TypeString(),
	)
}


func New(p *pcap.Packet) (ret *CATTPPacket,err error) {
	p.Decode()

	ret = &CATTPPacket{raw: p.Payload}

	//find lower header
	for _,h := range p.Headers {
		if ih,ok := h.(*pcap.Iphdr); ok {
			ret.ip = ih
		}

		if uh,ok := h.(*pcap.Udphdr); ok {
			ret.udp = uh
		}
	}

	if len(p.Payload) < len(ret.hdr) || ret.ip == nil || ret.udp == nil {
		return nil, fmt.Errorf("No cattp packet. %d/%d",len(p.Payload),18)
	}

	c := 0 // Amount of consumed header bytes
	for ;c<len(ret.hdr);c++ {
		ret.hdr[c] = p.Payload[c]
	}

	switch ret.Type() {
		case SYN:
			//parse additional header for SYN PDU
			for i:=0; i < len(ret.synpduhdr); {
				ret.synpduhdr[i] = p.Payload[c]
				i++
				c++
			}
			//parse variable Identification field.
			ret.identification = p.Payload[c:c+int(ret.synpduhdr[4])]
			c+=int(ret.synpduhdr[4])
		case RST:
			//just take the reason code here
			ret.rstpduhdr = p.Payload[c]
			c++
		default:
			//TODO: comment in once all other types have been implemented.
			//log.Printf("E|Unknown pdu type: %d",ret.Type())

	}

	ret.payload = p.Payload[c:]
	return
}
