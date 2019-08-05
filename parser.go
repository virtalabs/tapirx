package main

import (
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/virtalabs/tapirx/asset"
	"github.com/virtalabs/tapirx/decoder"
)

// readPacketsWithDecodingLayerParser reads packets from channel pchan until it is closed or there
// is an error.
func readPacketsWithDecodingLayerParser(
	done chan struct{},
	pchan chan gopacket.Packet,
	achan chan asset.Asset,
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
	appLayerDecoders := []decoder.PayloadDecoder{
		&decoder.HL7Decoder{},
		&decoder.DicomDecoder{},
		// &decoder.GenericDecoder{},
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
					logger.Printf("ARP Reply: %v is at %v\n",
						net.IP(arp.SourceProtAddress),
						net.HardwareAddr(arp.SourceHwAddress))
					arpTable.Add(
						net.HardwareAddr(arp.SourceHwAddress),
						net.IP(arp.SourceProtAddress))

					// Emit an asset.
					achan <- asset.Asset{
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
	for {
		select {
		case <-done:
			break
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
	logger.Println("packet worker exiting")

	wg.Done()
}
