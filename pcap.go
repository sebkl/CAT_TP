package cattp
//Package cattp implements CAT_TP packet decoding for pcap streams. 
//It is supposed to support both, cleint and server side implementations as well in the future.

import(
	"github.com/miekg/pcap"
	"fmt"
)

type Packet struct {
	Header
	ip *pcap.Iphdr
	udp *pcap.Udphdr
}

// String function voverts the packet data into a human readable logline.
func (p *Packet) String() string{
	return fmt.Sprintf("|%15s:%5d > %15s:%5d|%s v%d |hl %d |p %d > %d |dl %5d |sq %5d |ac %5d |ws %5d |ck %5d |pl %5d |mps %d |mss %d %s",
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
		p.WindowSize(),
		p.CheckSum(),
		len(p.Payload()),
		p.MaxPDUSize(),
		p.MaxSDUSize(),
		p.TypeString(),
	)
}

// NewPacket creates a new cattp packet based on an existing pcap packet. Error is returned if
// the pcap packet is not a cattp packet.
func NewPacket(p *pcap.Packet) (ret *Packet,err error) {
	p.Decode()

	ret = &Packet{}

	//find lower header
	for _,h := range p.Headers {
		if ih,ok := h.(*pcap.Iphdr); ok {
			ret.ip = ih
		}

		if uh,ok := h.(*pcap.Udphdr); ok {
			ret.udp = uh
		}
	}

	// assert whether is udp datagram
	if ret.ip == nil || ret.udp == nil {
		return nil, fmt.Errorf("Not a udp packet.")
	}

	//Parse the cattp header
	hdr,err := NewHeader(p.Payload)
	if err != nil {
		return
	}
	ret.Header = *hdr
	return
}
