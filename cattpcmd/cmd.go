package main

import (
	"os"
	"fmt"
	"github.com/miekg/pcap"
	. "github.com/sebkl/CAT_TP"
	"flag"
	"log"
	"encoding/hex"
	"strconv"
	"io"
)

type config struct {
	command string
	device string
	infile string
	outfile string
	filter string
	snaplen int
	format string
	clientCattpPort int
	identification string
	nibble bool
	log bool
	hexlog bool
}

var cfg config

//Initialize this package (initialize the command line parameter and their defaults)
func init() {
	flag.StringVar(&cfg.device, "i", "", "interface to open")
	flag.StringVar(&cfg.infile, "r", "", "file to read from")
	flag.StringVar(&cfg.outfile, "w", "", "pcap file to write output to")
	flag.IntVar(&cfg.snaplen, "s", 65535, "snaplen, defaults to 65535")
	flag.StringVar(&cfg.format, "f", "", "output format")
	flag.StringVar(&cfg.identification, "id", "", "identification")
	flag.BoolVar(&cfg.nibble, "n", false, "nibbled identification")
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

  %s -i <device> [options] log
  %s -r <filename> [options] log
  %s [options] connect <host:idp_port> <remote_cattp_port>
  %s [options] listen <host:udp_port> <local_cattp_port>

options:
`,e,e,e,e,e)
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

	var handle *pcap.Pcap
	var err error

	// In case of logging, implicitly set log flag
	if cfg.log || cfg.command == "log" {
		Log = log.New(os.Stderr,"CATTP",log.Flags())
	}

	switch cfg.command {
		case "log":
			// Set filter command for libpcap
			if len(args) > 1 {
				cfg.filter = args[1]
			}

			if len(cfg.device) > 0 {
				Log.Printf("Opening device: %s",cfg.device)
				handle,err = pcap.OpenLive(cfg.device,int32(cfg.snaplen),true,1000)
			} else if len(cfg.infile) > 0 {
				handle,err = pcap.OpenOffline(cfg.infile)
			} else {
				printUsage("No source given.")
			}

			if len(cfg.filter) > 0 {
				handle.SetFilter(cfg.filter)
			}

			if err != nil {
				Log.Fatalf("Failed to open source: %s",err)
			}

			//TODO: Fix this ugly condition for file end detection.
			for x := handle.Next();len(cfg.infile) > 0 && x != nil;x = handle.Next() {
				if x != nil {
					func (p *pcap.Packet) {
						defer func() {
							if r := recover(); r != nil {
								Log.Printf("Could not decode packet: %s \n %s",r, p)
							}
						}()

						p.Decode() // Decode pcap packet
						if cp,err := NewPacket(p); err == nil {
							fmt.Println(cp)
							if cfg.hexlog {
								fmt.Println(hex.Dump(cp.Raw()))
							}
						}
					}(x)
				}
			}

		case "connect":
			if len(args) < 3 {
				printUsage("Unsufficient arguments for '%s' command.", cfg.command)
			}

			addr := args[1]
			cattp_port := mustParsePort(args[2])
			id := []byte(cfg.identification)
			if cfg.nibble {
				id = Nibble(id)
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
