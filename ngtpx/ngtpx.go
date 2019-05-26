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
)

// NetStats holds network statistics during execution.
type NetStats struct {
	sync.Mutex
	decodingErrors map[string]int
}

// NewNetStats returns a new NetStats object.
func NewNetStats() *NetStats {
	ns := &NetStats{}
	ns.decodingErrors = make(map[string]int)
	return ns
}

// AddDecodingError records that a single decoding error occurred.
func (n *NetStats) AddDecodingError(err error) {
	n.Lock()
	defer n.Unlock()

	if err != nil {
		n.decodingErrors[err.Error()]++
	}
}

var (
	fileName     = flag.String("pcap", "", "pcap file to read")
	iface        = flag.String("iface", "", "interface to listen on")
	emitInterval = flag.Int("emit-interval", 10,
		"how often (in seconds) to emit assets to an API endpoint")

	arpTable *ArpTable
	netStats *NetStats
)

func main() {
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

	netStats = NewNetStats()
	defer fmt.Printf("%v\n", netStats)

	numWorkers := runtime.NumCPU()
	readPacketsFromHandle(handle, numWorkers)
}

func readPacketsFromHandle(handle *pcap.Handle, numWorkers int) {
	packets := gopacket.NewPacketSource(handle, handle.LinkType())
	pchan := packets.Packets()
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
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

	defer wg.Done()

	for packet := range pchan {
		err := parser.DecodeLayers(packet.Data(), &decodedLayers)
		if err != nil {
			// decoding stack doesn't know how to decode this packet
			netStats.AddDecodingError(err)
			continue
		}

		for _, layerType := range decodedLayers {
			switch layerType {
			case layers.LayerTypeARP:
				if arp.Operation == layers.ARPReply {
					log.Printf("ARP Reply: %v is at %v\n",
						net.IP(arp.SourceProtAddress),
						net.HardwareAddr(arp.SourceHwAddress))
					arpTable.Add(
						net.HardwareAddr(arp.SourceHwAddress),
						net.IP(arp.SourceProtAddress))
				}
			case layers.LayerTypeIPv4:
				log.Printf("Got an IPv4 packet from %s to %s\n",
					ip4.SrcIP.String(), ip4.DstIP.String())
			case layers.LayerTypeIPv6:
				log.Printf("Got an IPv6 packet from %s to %s\n",
					ip6.SrcIP.String(), ip6.DstIP.String())
			case layers.LayerTypeTCP:
				log.Println("Got a TCP packet")
			case layers.LayerTypeUDP:
				log.Println("Got a UDP packet")
			case gopacket.LayerTypePayload:
				// appLayer := packet.ApplicationLayer()
				log.Printf("Payload: %d bytes\n", len(payload.Payload()))
			}
		}
	}
}
