package main

import (
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/virtalabs/tapirx/decoder"
)

// readPacketsWithDecodingLayerParser reads packets from channel pchan until it is closed or there
// is an error.
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

	// Set of decoders against which each incoming packet will be tested. First one wins.
	appLayerDecoders := []decoder.PayloadDecoder{
		&decoder.HL7Decoder{},
		&decoder.DicomDecoder{},
		&decoder.GenericDecoder{},
	}
	for _, decoder := range appLayerDecoders {
		if err := decoder.Initialize(); err != nil {
			panic(err)
		}
	}

	for packet := range pchan {
		err := parser.DecodeLayers(packet.Data(), &decodedLayers)
		if err != nil {
			// decoding stack doesn't know how to decode this packet, but that's OK
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
			case gopacket.LayerTypePayload:
				appLayer := packet.ApplicationLayer()
				for _, d := range appLayerDecoders {
					decodingResult, err := d.DecodePayload(&appLayer)
					if err == nil {
						logger.Printf("Found a %s via %s\n",
							decodingResult.Identifier, decodingResult.Provenance)
					}
				}
			}
		}
	}

	wg.Done()
}
