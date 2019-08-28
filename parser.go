// Copyright 2019 Virta Laboratories, Inc.  All rights reserved.
/*
Packet parsing.
*/

package tapirx

import (
	"log"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ReadPacketsWithDecodingLayerParser reads packets from channel pchan until it
// is closed or there is an error.
func ReadPacketsWithDecodingLayerParser(
	done chan struct{},
	pchan chan gopacket.Packet,
	achan chan Asset,
	arpTable *ArpTable,
	wg *sync.WaitGroup) {

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

	// Set of decoders against which each incoming packet will be tested. First one wins.
	appLayerDecoders := []PayloadDecoder{
		&HL7Decoder{},
		&DicomDecoder{},
		// &GenericDecoder{},
	}
	for _, decoder := range appLayerDecoders {
		if err := decoder.Initialize(); err != nil {
			panic(err)
		}
	}

	processLayers := func(packet gopacket.Packet, decoded []gopacket.LayerType) {
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeARP:
				if arp.Operation == layers.ARPReply {
					log.Printf("ARP Reply: %v is at %v\n",
						net.IP(arp.SourceProtAddress),
						net.HardwareAddr(arp.SourceHwAddress))
					arpTable.Add(
						net.HardwareAddr(arp.SourceHwAddress),
						net.IP(arp.SourceProtAddress))

					// Emit an asset.
					achan <- Asset{
						MACAddress: net.HardwareAddr(arp.SourceHwAddress).String(),
					}
				}
			case gopacket.LayerTypePayload:
				appLayer := packet.ApplicationLayer()
				for _, d := range appLayerDecoders {
					_, err := d.DecodePayload(&appLayer)
					if err == nil {
						// TODO: make an asset
					}
				}
			}
		}
	}

packetLoop:
	/* Main loop: when a Packet is available from the packet source channel, attempt to make sense
	   of it by passing it to processLayers(). Shut down cleanly if a signal arrives from the done
	   channel. */
	for {
		select {
		case <-done:
			break packetLoop
		case p, ok := <-pchan:
			if !ok {
				break packetLoop
			}
			if err := parser.DecodeLayers(p.Data(), &decodedLayers); err != nil {
				// decoding stack doesn't know how to decode this packet, so ignore it
				continue
			}
			processLayers(p, decodedLayers)
		}
	}
	log.Println("packet worker exiting")

	wg.Done()
}
