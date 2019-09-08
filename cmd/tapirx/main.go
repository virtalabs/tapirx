// Copyright 2018-2019 Virta Laboratories, Inc.  All rights reserved.
/*
Tapirx passively discovers and identifies medical devices from raw network
traffic.

Source code: https://github.com/virtalabs/tapirx/

Inputs

This tool may be run against prerecorded traffic captures in individual pcap
files, or it may be run indefinitely on a live network interface connected to a
feed of network traffic (e.g., a SPAN port).

 # Load packets from a pcap file
 tapirx -pcap foo.pcap [...]

 # List available network interfaces and exit
 tapirx -interfaces

 # Read packets from the eth0 interface
 tapirx -iface eth0 [...]

You can use standard BPF expressions to filter the traffic you capture live or
extract from pcap files.

 # capture HL7 traffic
 tapirx -bpf "port 2575" [...]

 # capture DICOM traffic on port 11112
 tapirx -bpf "port 11112" [...]

Outputs

This tool can feed the results of its discovery and identification to other
systems via REST API endpoints. You may want to feed this information to a
system of record that tracks your networked assets.

 tapirx -apiurl https://my-system-of-record.example.com/api/devices [...]

To run against a BlueFlow server (https://virtalabs.com/blueflow), the command
line will look like

 tapirx -apiurl https://my-blueflow-instance/api/assets/upsert -apitoken <my API token> [...]

Runtime Help

Run this tool with the "-help" option to see runtime options.
 tapirx -help
*/
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
	"github.com/virtalabs/tapirx"
)

var (
	fileName   = flag.String("pcap", "", "pcap file to read")
	listIfaces = flag.Bool("interfaces", false, "List all network interfaces and exit")
	iface      = flag.String("iface", "", "Interface to listen on")
	bpfExpr    = flag.String("bpf", "", "BPF filtering expression")
	numWorkers = flag.Int("workers", runtime.NumCPU(),
		"Number of concurrent processes decoding packets")
	arpMaxAge    = flag.Duration("arp-max-age", 4*time.Hour, "Maximum age of ARP table entries")
	emitInterval = flag.Duration("emit-interval", 10*time.Second,
		"How often to emit assets")
	version = flag.Bool("version", false, "Show version information and exit")

	csvOutput = flag.String("csv", "", "CSV file to write")
	apiOutput = flag.String("apiUrl", "", "REST API endpoint to submit to")
	apiToken  = flag.String("apiToken", "", "API token to submit to REST API endpoint")

	logger *log.Logger
)

func main() {
	logger = log.New(os.Stderr, "INFO: ", log.LstdFlags)
	flag.Parse()

	if *version {
		fmt.Printf("%s %s\n", tapirx.ProductName, tapirx.Version)
		os.Exit(0)
	}

	if *listIfaces {
		tapirx.ListInterfaces()
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
			logger.Fatalln(err)
		}
	} else if *fileName != "" {
		if handle, err = pcap.OpenOffline(*fileName); err != nil {
			logger.Fatalln(err)
		}
	}

	// Optionally apply a BPF expression (a "filter") to the packet source
	if err := handle.SetBPFFilter(*bpfExpr); err != nil {
		logger.Fatalln(err)
	}

	// Set up an ARP table to map between IP addresses and MAC addresses throughout the course of
	// the capture. Expire entries older than 4 hours (default on most Cisco devices) every minute.
	arpTable := tapirx.NewArpTable(4*time.Hour, 1*time.Minute)

	done := make(chan struct{})
	cleanedUp := false
	cleanup := func() {
		if cleanedUp {
			return
		}
		logger.Println("Exiting cleanly.")
		close(done)
		cleanedUp = true
	}
	defer cleanup()
	registerCleanupHandler(cleanup)

	// The packet-to-Asset-to-server pipeline works as follows:
	//
	//                / (Decoder worker) \
	//   Source -->  {  (Decoder worker)  } --> Sink
	//                \ (...)            /
	//
	// The interesting work of making sense of packet payloads happens in the decoder workers, but
	// because a single decoder worker might not be able to keep up with incoming packets from a
	// fast source (e.g., a live Ethernet interface), we spawn numWorkers of them.
	//
	// The stages are set up in reverse order so that each pipeline stage is ready to receive before
	// anything tries to send to it.
	assets := tapirx.NewAssetSet()
	go assets.ConsumeAssets()

	// Create an AssetEmitter that will emit Assets somewhere; otherwise emit to log
	var emitter tapirx.AssetEmitter
	// XXX choose an emitter based on flags
	// emitter = tapirx.LoggingEmitter{}
	if *csvOutput != "" {
		emitter, err = tapirx.NewCSVEmitter(*csvOutput)
		if err != nil {
			logger.Fatalln("Invalid emitter")
		}
	} else if *apiOutput != "" {
		emitter = tapirx.NewAPIClient(*apiOutput, *apiToken, tapirx.Version,
			3, true)
	} else {
		emitter = tapirx.LoggingEmitter{}
	}
	periodicEmit := time.NewTicker(*emitInterval / 10)
	go func() {
		for range periodicEmit.C {
			fmt.Println("Emitting!")
			emitter.EmitSet(assets)
		}
	}()
	defer func() {
		emitter.EmitSet(assets)
		emitter.Close()
	}()

	pchan := gopacket.NewPacketSource(handle, handle.LinkType()).Packets() // source

	// Create a set of packet workers that will read from pchan until pchan runs out of packets or
	// the done channel is closed (by, e.g., a signal handler).
	logger.Printf("Will use %d worker threads\n", *numWorkers)
	var wg sync.WaitGroup
	for i := 0; i < *numWorkers; i++ {
		wg.Add(1)
		go tapirx.ReadPacketsWithDecodingLayerParser(done, pchan, assets.C, arpTable, &wg)
	}
	wg.Wait()
}
