// Unit tests for HL7 v2 decoding

package main

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func TestHL7DecodeFile(t *testing.T) {
	handle, err := pcap.OpenOffline("testdata/HL7-ADT-UDI-PRT.pcap")
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		app := packet.ApplicationLayer()
		if app == nil {
			continue // Ignore packets without an application layer
		}

		_, _, err := hl7Decode(&app)
		if err != nil {
			panic(err)
		}
	}
}

func appLayerFromString(s string) *gopacket.ApplicationLayer {
	bytes := []byte(s)
	appLayer := gopacket.ApplicationLayer(gopacket.Payload(bytes))
	return &appLayer
}

func TestHL7DecodeTooShort(t *testing.T) {
	appLayer := appLayerFromString("MSH")
	ident, _, err := hl7Decode(appLayer)
	if ident != "" {
		t.Errorf("Got identifier when none was expected")
	}
	if err == nil {
		t.Errorf("Expected an error from too-short HL7 message")
	}
}

func testHL7DecodeEmpty(s string, t *testing.T) {
	appLayer := appLayerFromString(s)
	ident, _, err := hl7Decode(appLayer)
	if ident != "" {
		t.Errorf("Got identifier when none was expected")
	}
	if err != nil {
		panic(err)
	}
}

func TestHL7DecodeEmpty1(t *testing.T) { testHL7DecodeEmpty("MSH|^~\\&", t) }
func TestHL7DecodeEmpty2(t *testing.T) { testHL7DecodeEmpty("MSH|^~\\&|", t) }

func identFromString(s string, t *testing.T) string {
	appLayer := appLayerFromString(s)
	ident, _, err := hl7Decode(appLayer)
	if err != nil {
		panic(err)
	}
	return ident
}

func TestHL7IdentFromPRT(t *testing.T) {
	t.Skip("TODO")
	parsed := identFromString("MSH|^~\\&|PRT|A|B|C|D|E|F|G|H|I|Hospira Plum A+|", t)
	if parsed != "Hospira Plum A+" {
		t.Errorf("Failed to parse identifier from string; got '%s'", parsed)
	}
}
