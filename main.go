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
	"io"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	// import layers to run its init function
	_ "github.com/google/gopacket/layers"
)

var (
	logger  *log.Logger
	verbose bool
	stats   Stats
)

func setupLogging(debug bool) {
	var traceDest io.Writer
	traceDest = ioutil.Discard
	if debug {
		traceDest = os.Stderr
	}
	logger = log.New(traceDest, "INFO: ", log.LstdFlags)
}

func listInterfaces() {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}
	for _, iface := range ifaces {
		if runtime.GOOS == "windows" {
			// On Windows, device names are ugly, like
			// "\Device\NPF_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}",
			// so display a more descriptive name too.
			fmt.Printf("%s\t(%s)\n", iface.Name, iface.Description)
		} else {
			fmt.Println(iface.Name)
		}
	}
}

func main() {
	// Default client ID is this computer's hostname
	hostname, err := os.Hostname()
	if err != nil {
		logger.Println("Failed to get hostname")
		hostname = "localhost"
	}

	// parse command-line flags
	flag.BoolVar(&verbose, "verbose", false, "Show verbose output")
	debug := flag.Bool("debug", false, "Show debug output")
	ifaceName := flag.String("iface", "eth0", "Interface to listen on")
	bpfExpr := flag.String("bpf", "", "BPF filtering expression")
	fileName := flag.String("pcap", "", "pcap file to read")
	apiURL := flag.String("apiurl", "", "Upload API url")
	apiToken := flag.String("apitoken", "", "Upload API token")
	apiLimit := flag.Int("apilimit", 10, "Limit of concurrent requests to API")
	clientID := flag.String("clientid", hostname, "Client ID sent with API requests")
	statsFlag := flag.Bool("stats", false, "Show statistics (as JSON data) before exiting")
	version := flag.Bool("version", false, "Show version information and exit")
	packetLimit := flag.Int("limit", 0, "Exit after N packets, 0 for unlimited")
	sequential := flag.Bool("sequential", false, "Process packets sequentially")
	csvFilename := flag.String("csv", "", "Stream assets to CSV file")
	listIfaces := flag.Bool("interfaces", false, "List all network interfaces and exit")
	mqttURL := flag.String("mqtt", "", "Send to MQTT URI")
	flag.Parse()

	setupLogging(*debug)
	stats = *NewStats()

	if *version {
		fmt.Printf("%s %s\n", ProductName, Version)
		os.Exit(0)
	}

	if *listIfaces {
		listInterfaces()
		os.Exit(0)
	}

	if *statsFlag {
		// Print stats before exit via Ctrl-C-esque interrupt
		registerInterruptHandler()
	}

	logger.Printf("starting %s %s (%s)\n", ProductName, Version, runtime.GOOS)
	defer logger.Printf("exiting %s\n", ProductName)

	var handle *pcap.Handle
	// Read from file or from interface (and bail if there's a failure)
	if *fileName != "" {
		logger.Printf("read from file %v\n", *fileName)
		handle, err = pcap.OpenOffline(*fileName)
	} else {
		logger.Printf("listen on interface %v\n", *ifaceName)
		handle, err = pcap.OpenLive(*ifaceName, 1600, true, pcap.BlockForever)
	}
	if err != nil {
		panic(err)
	}

	// Set a Berkeley Packet Filter (BPF) filter if one is provided
	if *bpfExpr != "" {
		logger.Printf("BPF filter expression: [%s]\n", *bpfExpr)
		if err := handle.SetBPFFilter(*bpfExpr); err != nil {
			panic(err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Configure the API client module
	apiClientEnabled := *apiURL != ""
	apiClient := NewAPIClient(*apiURL, *apiToken, *clientID, *apiLimit, apiClientEnabled)

	// Configure CSV writer module
	assetCSVWriter, err := NewAssetCSVWriter(*csvFilename)
	if err != nil {
		panic(err)
	}
	if assetCSVWriter != nil {
		defer assetCSVWriter.Close()
	}

	// Configure NQTT writer module
	mqttWriter, err := NewMQTTWriter(*mqttURL)
	if err != nil {
		panic(err)
	}
	if mqttWriter != nil {
		defer mqttWriter.Close()
	}

	// A WaitGroup will let us wait until all threads have finished before exit
	// http://goinbigdata.com/golang-wait-for-all-goroutines-to-finish/
	var waitGroup sync.WaitGroup

	// Make a set of decoders against which each incoming packet will be tested.
	appLayerDecoders := []PayloadDecoder{
		&HL7Decoder{},
		&DicomDecoder{},
	}
	for _, decoder := range appLayerDecoders {
		if err := decoder.Initialize(); err != nil {
			panic(err)
		}
	}

	// Handle a sequence of packets. If sequential is set, handle every packet in the main thread.
	// Otherwise, spawn a goroutine for each packet.
	nPackets := 0
	for packet := range packetSource.Packets() {
		if *packetLimit > 0 && nPackets >= *packetLimit {
			logger.Printf("Packet limit %d reached; exiting.\n", *packetLimit)
			break
		}
		waitGroup.Add(1)
		if *sequential {
			handlePacket(packet, appLayerDecoders, apiClient, assetCSVWriter, mqttWriter, &waitGroup)
		} else {
			go handlePacket(packet, appLayerDecoders, apiClient, assetCSVWriter, mqttWriter, &waitGroup)
		}
		nPackets++
	}

	// Block until we receive a notification from the workers.
	waitGroup.Wait()

	// Print stats
	if *statsFlag {
		fmt.Println(stats.String())
	}

}
