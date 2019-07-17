package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	fileName     = flag.String("pcap", "", "pcap file to read")
	iface        = flag.String("iface", "", "interface to listen on")
	emitInterval = flag.Int("emit-interval", 10,
		"How often (in seconds) to emit assets to an API endpoint")
	numWorkers = flag.Int("workers", runtime.NumCPU(),
		"Number of concurrent processes decoding packets")
	listIfaces = flag.Bool("interfaces", false, "List all network interfaces and exit")
	version    = flag.Bool("version", false, "Show version information and exit")
	bpfExpr    = flag.String("bpf", "", "BPF filtering expression")

	arpTable *ArpTable
	logger   *log.Logger
)

func main() {
	logger = log.New(os.Stderr, "INFO: ", log.LstdFlags)
	flag.Parse()

	if *version {
		fmt.Printf("%s %s\n", ProductName, Version)
		os.Exit(0)
	}

	if *listIfaces {
		listInterfaces()
		os.Exit(0)
	}

	if *iface != "" && *fileName != "" {
		fmt.Fprintln(os.Stderr, "Specify -iface or -pcap, but not both")
		os.Exit(1)
	} else if *iface == "" && *fileName == "" {
		fmt.Fprintln(os.Stderr, "Specify -iface or -pcap")
		os.Exit(1)
	}

	// Configure a packet source: either a "live" interface or a pcap file
	var handle *pcap.Handle
	var err error
	if *iface != "" {
		if handle, err = pcap.OpenLive(*iface, 1600, true, pcap.BlockForever); err != nil {
			log.Fatalln(err)
		}
	} else if *fileName != "" {
		if handle, err = pcap.OpenOffline(*fileName); err != nil {
			log.Fatalln(err)
		}
	}

	// Optionally apply a BPF expression (a "filter") to the packet source
	if err := handle.SetBPFFilter(*bpfExpr); err != nil {
		log.Fatalln(err)
	}

	// Set up an ARP table to map between IP addresses and MAC addresses throughout the course of
	// the capture
	arpTable = NewArpTable()
	defer arpTable.Print()
	go func() {
		timer := time.NewTicker(5 * time.Second)
		for range timer.C {
			arpTable.Print()
		}
	}()

	readPacketsFromHandle(handle, *numWorkers)
	fmt.Println("Exiting.")
}

func readPacketsFromHandle(handle *pcap.Handle, numWorkers int) {
	logger.Printf("Will use %d worker threads\n", numWorkers)

	// channel that will emit packets as the packet parser finds them
	pchan := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	defer close(pchan)

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go readPacketsWithDecodingLayerParser(pchan, &wg)
	}
	wg.Wait()
}
