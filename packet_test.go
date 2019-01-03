package main

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	// import layers to run its init function
	_ "github.com/google/gopacket/layers"
)

func TestPacketParseSimple(t *testing.T) {
	// Read a small pcap file and process the packets using handlePacket.  Use the
	// statistics generated at the end to check for correctness.

	setupLogging(false)

	// Initialize objects later used by handlePacket
	stats := NewStats()
	apiClient := NewAPIClient("", "", "", 1, false)
	assetCSVWriter, err := NewAssetCSVWriter("")
	if err != nil {
		panic(err)
	}

	// Read a pcap file
	handle, err := pcap.OpenOffline("testdata/HL7-ADT-UDI-PRT.pcap")
	if err != nil {
		panic(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Handle each packet from the pcap file
	var numPackets uint64
	for packet := range packetSource.Packets() {
		handlePacket(packet, stats, apiClient, assetCSVWriter, nil)
		numPackets++
	}

	// Check stats
	if stats.Provenances["HL7 PRT-10"] != 1 {
		t.Errorf("Not enough HL7 packets")
	}
	if stats.TotalPacketCount != numPackets {
		t.Errorf("Wrong total packet count: %d (wanted %d)",
			stats.TotalPacketCount, numPackets)
	}

}
