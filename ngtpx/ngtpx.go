package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/virtalabs/tapirx/decoder"
)

var (
	fileName     = flag.String("pcap", "", "pcap file to read")
	iface        = flag.String("iface", "", "interface to listen on")
	emitInterval = flag.Int("emit-interval", 10,
		"How often (in seconds) to emit assets to an API endpoint")
	numWorkers = flag.Int("workers", runtime.NumCPU(),
		"Number of concurrent processes decoding packets")

	arpTable *ArpTable
	logger   log.Logger
)

func main() {
	logger = *log.New(os.Stderr, "INFO: ", log.LstdFlags)
	flag.Parse()

	// Check that the user provided either a pcap file or an interface on whih to listen (not both)
	var handle *pcap.Handle
	var err error
	if *iface != "" && *fileName != "" {
		fmt.Fprintln(os.Stderr, "Specify -iface or -pcap, but not both")
		os.Exit(1)
	} else if *iface != "" {
		if handle, err = pcap.OpenLive(*iface, 1600, true, pcap.BlockForever); err != nil {
			log.Fatalln(err)
		}
	} else if *fileName != "" {
		if handle, err = pcap.OpenOffline(*fileName); err != nil {
			log.Fatalln(err)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Specify -iface or -pcap")
		os.Exit(1)
	}

	arpTable = NewArpTable()
	defer arpTable.Print()
	go func() {
		timer := time.NewTicker(5 * time.Second)
		for range timer.C {
			arpTable.Print()
		}
	}()

	readPacketsFromHandle(handle, *numWorkers)
}

func readPacketsFromHandle(handle *pcap.Handle, numWorkers int) {
	packets := gopacket.NewPacketSource(handle, handle.LinkType())
	pchan := packets.Packets()
	var wg sync.WaitGroup
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go readPacketsWithDecodingLayerParser(pchan, &wg)
	}
	wg.Wait()
}

func readPacketsWithDecodingLayerParser(pchan <-chan gopacket.Packet, wg *sync.WaitGroup) {
	var (
		eth     layers.Ethernet
		arp     layers.ARP
		ip4     layers.IPv4
		ip6     layers.IPv6
		udp     layers.UDP
		tcp     layers.TCP
		payload gopacket.Payload
	)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet, // base layer type
		&eth, &arp, &ip4, &ip6, &udp, &tcp, &payload)
	decodedLayers := []gopacket.LayerType{}

	// Make a set of decoders against which each incoming packet will be tested.
	appLayerDecoders := []decoder.PayloadDecoder{
		&decoder.HL7Decoder{Logger: &logger},
		&decoder.DicomDecoder{Logger: &logger},
	}
	for _, decoder := range appLayerDecoders {
		if err := decoder.Initialize(); err != nil {
			panic(err)
		}
	}

	defer wg.Done()

	for packet := range pchan {
		err := parser.DecodeLayers(packet.Data(), &decodedLayers)
		if err != nil {
			// decoding stack doesn't know how to decode this packet
			continue
		}

		for _, layerType := range decodedLayers {
			switch layerType {
			case layers.LayerTypeARP:
				if arp.Operation == layers.ARPReply {
					logger.Printf("ARP Reply: %v is at %v\n",
						net.IP(arp.SourceProtAddress),
						net.HardwareAddr(arp.SourceHwAddress))
					arpTable.Add(
						net.HardwareAddr(arp.SourceHwAddress),
						net.IP(arp.SourceProtAddress))
				}
			case layers.LayerTypeIPv4:
				logger.Printf("Got an IPv4 packet from %s to %s\n",
					ip4.SrcIP.String(), ip4.DstIP.String())
			case layers.LayerTypeIPv6:
				logger.Printf("Got an IPv6 packet from %s to %s\n",
					ip6.SrcIP.String(), ip6.DstIP.String())
			case layers.LayerTypeTCP:
				logger.Println("Got a TCP packet")
			case layers.LayerTypeUDP:
				logger.Println("Got a UDP packet")
			case gopacket.LayerTypePayload:
				appLayer := packet.ApplicationLayer()
				logger.Printf("Payload: %d bytes\n", len(payload.Payload()))
				for _, decoder := range appLayerDecoders {
					identifier, provenance, err := decoder.DecodePayload(&appLayer)
					if err == nil {
						logger.Printf("Found a %s via %s\n", identifier, provenance)
					} else {
						logger.Println("Not a packet of this type")
					}
				}
			}
		}
	}
}
