package main

import (
	"io/ioutil"
	"log"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/virtalabs/tapirx/asset"
	"github.com/virtalabs/tapirx/decoder"

	// import layers to run its init function
	_ "github.com/google/gopacket/layers"
)

var testDecoders []decoder.PayloadDecoder

func init() {
	logger := log.New(ioutil.Discard, "", log.LstdFlags)
	testDecoders = []decoder.PayloadDecoder{
		&decoder.HL7Decoder{Logger: logger},
		&decoder.DicomDecoder{Logger: logger},
	}
	for _, testDecoder := range testDecoders {
		if err := testDecoder.Initialize(); err != nil {
			panic("Failed to initialize decoders")
		}
	}
}

func TestPacketParseSimple(t *testing.T) {
	// Read a small pcap file and process the packets using handlePacket.  Use the
	// statistics generated at the end to check for correctness.

	setupLogging(false)

	// Initialize objects later used by handlePacket
	stats = *NewStats()
	apiClient := NewAPIClient("", "", "", 1, false)
	assetCSVWriter, err := asset.NewAssetCSVWriter("")
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
		handlePacket(packet, testDecoders, apiClient, assetCSVWriter, nil)
		numPackets++
	}

	// Check stats
	if nPrt16 := stats.Provenances["HL7 PRT-16"]; nPrt16 != 1 {
		t.Errorf("Not enough HL7 packets: %d (wanted %d)", nPrt16, 1)
	}
	if nPkts := stats.TotalPacketCount; nPkts != numPackets {
		t.Errorf("Wrong total packet count: %d (wanted %d)", nPkts, numPackets)
	}

}

// Create an empty Packet and ignore it
func TestSkipEmptyPacket(t *testing.T) {
	var data []byte
	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	stats = *NewStats()
	handlePacket(pkt, testDecoders, nil, nil, nil)

	if stats.TotalPacketCount != 1 {
		t.Errorf("Wrong number of packets")
	}

	if len(stats.Identifiers) != 0 {
		t.Errorf("Expected to find no identifiers; found %d", len(stats.Identifiers))
	}
}

// Create an empty Packet to measure the overhead of ignoring it
func BenchmarkSkipEmptyPacket(b *testing.B) {
	var data []byte
	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	stats = *NewStats()
	for i := 0; i < b.N; i++ {
		handlePacket(pkt, testDecoders, nil, nil, nil)
	}
}
