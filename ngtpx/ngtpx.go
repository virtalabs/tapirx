package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func emitAssets() {
	log.Println("emitAssets()")
}

func main() {
	fileName := flag.String("pcap", "", "pcap file to read")
	iface := flag.String("iface", "", "interface to listen on")
	emitInterval := flag.Int("emit-interval", 10,
		"how often (in seconds) to emit assets to an API endpoint")
	flag.Parse()

	var handle *pcap.Handle
	var err error
	if *iface != "" {
		handle, err = pcap.OpenLive(*iface, 1600, true, pcap.BlockForever)
	} else if *fileName != "" {
		handle, err = pcap.OpenOffline(*fileName)
	} else {
		fmt.Fprintln(os.Stderr, "Specify -iface or -pcap")
		os.Exit(1)
	}
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf("%T", time.Second)
	assetEmitter := time.NewTicker(time.Duration(*emitInterval) * time.Second)
	defer assetEmitter.Stop()
	go func() {
		for range assetEmitter.C {
			emitAssets()
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go readPackets(handle, &wg)
	wg.Wait()
}

func readPackets(handle *pcap.Handle, wg *sync.WaitGroup) {
	defer wg.Done()
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	var packet gopacket.Packet
	pkts := 0
	for {
		select {
		case packet = <-in:
			if packet == nil {
				return
			}
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp, ok := arpLayer.(*layers.ARP)
			if !ok {
				fmt.Println("not ok")
				continue
			}
			if arp.Operation != layers.ARPReply {
				continue
			}
			// Note:  we might get some packets here that aren't responses to ones we've sent,
			// if for example someone else sends US an ARP request.  Doesn't much matter, though...
			// all information is good information :)
			fmt.Printf("%06d: IP %v is at %v\n", pkts, net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
			pkts++
		}
	}
}
