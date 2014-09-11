package cattp

import (
	"fmt"
)

type Dumper interface {
	Dump(data []byte) string
}

type HexDumper struct {}

func (h HexDumper) Dump(data []byte) string {
	return fmt.Sprintf("%X",data)
}

var OctetDumper Dumper = HexDumper{}
