package main

import (
	"os"
	"fmt"
	. "github.com/sebkl/CAT_TP"
	"flag"
	"encoding/hex"
	"strconv"
	"io"
	"log"
)

type config struct {
	command string
	snaplen int
	format string
	clientCattpPort int
	identification string
	nibble bool
	hexdecode bool
	log bool
	hexlog bool
}

var cfg config

//Initialize this package (initialize the command line parameter and their defaults)
func init() {
	flag.StringVar(&cfg.identification, "id", "", "identification")
	flag.BoolVar(&cfg.nibble, "n", false, "nibbled identification")
	flag.BoolVar(&cfg.hexdecode, "he", false, "hex decode identification (provide hex encoded)")
	flag.IntVar(&cfg.clientCattpPort, "p",1, "client cattp port")
	flag.BoolVar(&cfg.log,"v",false,"verbose logging")
	flag.BoolVar(&cfg.hexlog,"h",false,"hex logging")
}


// Print usage information about command line parameters.
func printUsage(args ...string) {
	e := os.Args[0]
	fmt.Fprintf(os.Stderr,`
usage: %s [options] <command> <args>

Commands: 

  %s [options] connect <host:idp_port> <remote_cattp_port>
  %s [options] listen <host:udp_port> <local_cattp_port>

options:
`,e,e,e)
	flag.PrintDefaults()

	for _,a := range args {
		fmt.Fprintf(os.Stderr,"%s\n",a)
	}
	os.Exit(1)
}

//Convert a string into a uint16 port.
func mustParsePort(in string) (cattp_port uint16) {
	cattp_port = uint16(1)
	if pi,err := strconv.Atoi(in); err == nil {
		cattp_port = uint16(pi)
	} else {
		printUsage(fmt.Sprintf("Invalid CAT_TP port: %s",err))
	}
	return
}

//Continuesly forward reader to writer
func forward(in io.Reader, out io.Writer) (err error){
	//reader := bufio.NewReader(in)
	buf := make([]byte,1024)
	var b,c,w int
	b = 0
	err = nil
	for ;err == nil; {
		c,err = in.Read(buf[b:])
		w,err = out.Write(buf[0:(b+c)])
		b = w
	}
	return
}

func main() {
	flag.Parse()
        args := flag.Args()

	if len(args) > 0 {
		cfg.command = args[0]
	}

	if cfg.log {
		Log = log.New(os.Stderr,"CATTP",log.Flags())
	}

	switch cfg.command {
		case "connect":
			if len(args) < 3 {
				printUsage("Unsufficient arguments for '%s' command.", cfg.command)
			}

			addr := args[1]
			cattp_port := mustParsePort(args[2])
			id := []byte(cfg.identification)
			var err error

			if cfg.hexdecode {
				id,err = hex.DecodeString(string(id))
				if err != nil {
					Log.Fatalf("Could not hex decode id '%s' : %s",string(id),err)
				}
				Log.Printf("Decoded id to '%s'",hex.Dump(id))
			}

			if cfg.nibble {
				id = Nibble(id)
				Log.Printf("Nibbled id to '%s'",hex.Dump(id))
			}

			con,err := ConnectWait(addr, uint16(cfg.clientCattpPort), cattp_port, id,
				func (c *Connection,ps []*Header, data []byte) {
					fmt.Printf("%s>\n%s",c.RemoteAddr().String(),hex.Dump(data))
				})

			if err != nil {
				Log.Fatalf("Connect failed: %s",err)
			}

			Log.Fatalf("Sending Data failed: %s",forward(os.Stdin,con))

		case "listen":
			if len(args) < 3 {
				printUsage("Unsufficient arguments for '%s' command.", cfg.command)
			}

			addr := args[1]
			cattp_port := mustParsePort(args[2])

			err := KeepListening(addr, cattp_port,
				func (c *Connection,ps []*Header, data []byte) {
					fmt.Printf("%s>\n%s",c.RemoteAddr().String(),hex.Dump(data))
				},
				SocketParameters{
					CONNECTION_HANDLER: func(c *Connection) {
					Log.Printf("Incoming Connection from %s with identification: %s",c.RemoteAddr().String(),string(c.Identification()))
					}})

			Log.Fatalf("Server stopped: %s",err)
		default:
			printUsage(fmt.Sprintf("Unknown command: '%s'",cfg.command))
	}
}
