// Copyright 2018-2019 Virta Laboratories, Inc.  All rights reserved.
/*
Packet-handling nitty gritty.
*/

package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// decodeLayers extracts information from packets and stuffs any discovered
// metadata into the provided Asset object.
func decodeLayers(packet gopacket.Packet, asset *Asset) error {
	// Decode link, network, and transport layers to extract metadata about a
	// packet that may represent an asset.
	//
	// Ignore errors produced by DecodeLayer() because we can still get
	// information from the layers that didn't produce an error.
	//
	// Docs:
	// https://godoc.org/github.com/google/gopacket#hdr-Fast_Decoding_With_DecodingLayerParser
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp)
	decoded := []gopacket.LayerType{}
	logger.Println("Decode packet")
	parser.DecodeLayers(packet.Data(), &decoded)
	for _, layerType := range decoded {
		switch layerType {
		case layers.LayerTypeEthernet:
			asset.MACAddress = eth.SrcMAC.String()
			stats.AddLayer("Ethernet")
			logger.Println("  Eth", eth.SrcMAC, eth.DstMAC)
		case layers.LayerTypeIPv4:
			asset.IPv4Address = ip4.SrcIP.String()
			stats.AddLayer("IPv4")
			logger.Println("  IP4", ip4.SrcIP, ip4.DstIP)
		case layers.LayerTypeIPv6:
			asset.IPv6Address = ip6.SrcIP.String()
			stats.AddLayer("IPv6")
			logger.Println("  IP6", ip6.SrcIP, ip6.DstIP)
		case layers.LayerTypeTCP:
			logger.Printf("TCP %d->%d seq %d\n", tcp.SrcPort, tcp.DstPort, tcp.Seq)
			stats.AddLayer("TCP")
			if tcp.SYN {
				// If this packet has SYN+ACK, then the endpoint is accepting a
				// connection on the *source* port (i.e., it's the "server" side
				// of a new connection). If this packet has SYN but not ACK,
				// then it is *initiating* a connection to the *destination*
				// port (i.e., it's the "client" side of a new connection).
				if tcp.ACK {
					asset.ListensOnPort = tcp.SrcPort.String()
					asset.Provenance = "TCP handshake"
					stats.AddLayer("TCP/handshake")
					logger.Printf("  TCP server on %s\n", tcp.SrcPort)
				} else {
					asset.ConnectsToPort = tcp.DstPort.String()
					asset.Provenance = "TCP handshake"
					stats.AddLayer("TCP/handshake")
					logger.Printf("  TCP client to :%s\n", tcp.DstPort)
				}
			}
		}
	}
	return nil
}

// parseApplicationLayer extracts information from a packet's application layer,
// if one exists, and updates a provided Asset object.
func parseApplicationLayer(packet gopacket.Packet, decoders []PayloadDecoder, asset *Asset) error {
	app := packet.ApplicationLayer()
	if app == nil {
		return fmt.Errorf("No application layer")
	}

	// Update statstics
	stats.AddLayer("Application")

	// Try to decode the application layer using each decoder in turn, stopping
	// when a decoder succeeds or there are no decoders remaining.
	for _, decoder := range decoders {
		if !decoder.Wants(&app) {
			continue
		}
		decoderName := decoder.Name()
		identifier, provenance, err := decoder.DecodePayload(&app)
		if err == nil {
			// Success, we're done
			asset.Identifier = identifier
			asset.Provenance = provenance
			stats.AddLayer("Application/" + decoderName)
			break
		}
	}
	if asset.Identifier == "" {
		return fmt.Errorf("failed to find a decoder, no identifier")
	}

	return nil
}

// handlePacket extracts information from packets, invokes decoding functions
// that attempt to interpret the contents of application layers, updates
// packet-processing statistics, and optionally uploads its findings to a REST
// API endpoint.
func handlePacket(
	packet gopacket.Packet,
	appLayerDecoders []PayloadDecoder,
	apiClient *APIClient,
	assetCSVWriter *AssetCSVWriter,
	waitGroup *sync.WaitGroup,
) {
	if waitGroup != nil {
		defer waitGroup.Done()
	}

	// Initialize an empty Asset to store information learned during dissection
	asset := &Asset{}
	asset.LastSeen = time.Now()

	// Decode packet and update statistics
	stats.AddPacket()
	if err := decodeLayers(packet, asset); err != nil {
		stats.AddError(err)
		return
	} else if err := parseApplicationLayer(packet, appLayerDecoders, asset); err != nil {
		stats.AddError(err)
		return
	} else {
		stats.AddAsset(asset)
	}

	// Write to stdout and stderr
	bytesRepresentation, err := json.Marshal(asset)
	if err != nil {
		stats.AddError(err)
	}
	stringRepresentation := string(bytesRepresentation)
	if verbose {
		fmt.Println(stringRepresentation)
	}
	logger.Println(stringRepresentation)

	// Write to CSV file if requested by the user.
	if assetCSVWriter != nil && assetCSVWriter.Enabled() {
		if err := assetCSVWriter.Append(asset); err != nil {
			stats.AddError(err)
		}
	}

	// Upload to API if requested by the user.  If the user did not specify a
	// URL with a command line flag, the URL will be empty.
	if apiClient.enabled {
		if _, err := apiClient.Upload(asset); err != nil {
			logger.Println("API Upload error:", err)
			stats.AddUploadError(err)
		} else {
			stats.AddUpload()
		}
	}
}
