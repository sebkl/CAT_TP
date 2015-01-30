package main

import (
	"os"
	"fmt"
	"github.com/miekg/pcap"
	. "github.com/sebkl/CAT_TP/pcap"
	. "github.com/sebkl/CAT_TP"
	"flag"
	"log"
	"encoding/hex"
)

type config struct {
	command string
	device string
	infile string
	filter string
	snaplen int
	log bool
	hexlog bool
}

var cfg config

//Initialize this package (initialize the command line parameter and their defaults)
func init() {
	flag.StringVar(&cfg.device, "i", "", "interface to open")
	flag.StringVar(&cfg.infile, "r", "", "file to read from")
	flag.IntVar(&cfg.snaplen, "s", 65535, "snaplen, defaults to 65535")
	flag.BoolVar(&cfg.log,"v",false,"verbose logging")
	flag.BoolVar(&cfg.hexlog,"h",false,"hex logging")
}


// Print usage information about command line parameters.
func printUsage(args ...string) {
	e := os.Args[0]
	fmt.Fprintf(os.Stderr,`
usage: %s [options] [filter args]

Commands: 
  %s -i <device> [options] [filter args]
  %s -r <filename> [options] [filter args]

options:
`,e,e,e)
	flag.PrintDefaults()

	for _,a := range args {
		fmt.Fprintf(os.Stderr,"%s\n",a)
	}
	os.Exit(1)
}

func main() {
	flag.Parse()
        args := flag.Args()

	if len(args) > 0 {
		cfg.command = args[0]
	}

	var handle *pcap.Pcap
	var err error

	Log = log.New(os.Stderr,"CATTP",log.Flags())

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
}
