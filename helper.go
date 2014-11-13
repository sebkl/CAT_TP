package cattp

import (
	"log"
	"fmt"
	"io/ioutil"
)

const (
	LOGPREFIX = "CATTP"
)


type Dumper interface {
	Dump(data []byte) string
}

type HexDumper struct {}

func (h HexDumper) Dump(data []byte) string {
	return fmt.Sprintf("%X",data)
}

var OctetDumper Dumper = HexDumper{}
var Log *log.Logger

//Initialize the helper module
func init() {
	Log = log.New(ioutil.Discard,LOGPREFIX,log.Flags())
}

// EchoHandler is a default handler that just prints the payload
// to stdout.
func EchoHandler (c *Connection,ps []*Header, data []byte) {
	r,_ := c.Write(data)
	Log.Printf("Echoed data: %s/%d",string(data),r)
}

// LogHandler logs the packet structure to the logging framework.
func LogHandler(c *Connection,ps []*Header, data []byte) {
	Log.Printf(">#%X\n",data)
}


// BufferHandler is the default handler that pushes all incoming
// data to the corresponding buffer. This data can be read by using
// the io.Reader interface accordingly.
func BufferHandler (c *Connection,ps []*Header, data []byte) {
	dl := len(data)
	var err error
	for wl := 0;err == nil && wl < dl; {
		wl, err = c.inbuf.Write(data[wl:dl])
	}
}

//IgnoreHandler ignoresincoming bytes
func IgnoreHandler (c* Connection,ps []*Header, data []byte) {}

//switches the byte array per nibble (like big to little endian just with nibbles)
func Nibble(data []byte) []byte {
	ret := make([]byte,len(data))
	for i,b := range data {
		ret[i] = byte(b << 4) | byte(b >> 4)
	}
	return ret
}

