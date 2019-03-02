// Unit tests for HL7 v2 decoding

package main

import (
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var testHl7Decoder HL7Decoder

func init() {
	if err := testHl7Decoder.Initialize(); err != nil {
		panic("Failed to build queries")
	}
}

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

		_, _, err := testHl7Decoder.DecodePayload(&app)
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
	ident, _, err := testHl7Decoder.DecodePayload(appLayer)
	if ident != "" {
		t.Errorf("Got identifier when none was expected")
	}
	if err == nil {
		t.Errorf("Expected an error from too-short HL7 message")
	}
}

func testHL7DecodeEmpty(s string, t *testing.T) {
	appLayer := appLayerFromString(s)
	ident, _, err := testHl7Decoder.DecodePayload(appLayer)
	if ident != "" {
		t.Errorf("Got identifier when none was expected")
	}
	if err != nil {
		panic(err)
	}
}

func TestHL7DecodeEmpty1(t *testing.T) { testHL7DecodeEmpty("MSH|^~\\&", t) }
func TestHL7DecodeEmpty2(t *testing.T) { testHL7DecodeEmpty("MSH|^~\\&|", t) }

func identFromString(s string) string {
	appLayer := appLayerFromString(s)
	ident, _, err := testHl7Decoder.DecodePayload(appLayer)
	if err != nil {
		panic(err)
	}
	return ident
}

// Well-formed message header segment to be prepended to messages for testing
const okHL7Header = ("" +
	// Header and delimiter
	"MSH|^~\\&|" +

	// Envelope information
	"Sender|Sender Facility|" +
	"Receiver|Receiver Facility|" +

	// Timestamp (YYYYMMDDHHMM) + Security (blank)
	"201801131030||" +

	// Message type: ORU = observations & results
	"ORU^R01|" +

	// Control ID
	"CNTRL-12345|" +

	// Processing ID
	"P|" +

	// Version ID + segment delimiter (carriage return)
	"2.4\r")

func getNRecordString(nrec int) string {
	if nrec < 1 || nrec > 26 {
		return ""
	}
	alphas := make([]string, nrec)
	for i := 0; i < nrec; i++ {
		alphas[i] = string('A' + i)
	}
	return strings.Join(alphas, "|")
}

func TestNRecordString(t *testing.T) {
	if getNRecordString(-1) != "" || getNRecordString(0) != "" || getNRecordString(27) != "" {
		panic("Out-of-range n-record string broken")
	}

	if getNRecordString(1) != "A" {
		panic("1-record string broken")
	}

	if getNRecordString(3) != "A|B|C" {
		panic("3-record string broken")
	}
}

func TestHL7IdentFromOBX18(t *testing.T) {
	str := okHL7Header + "OBX|" + getNRecordString(17) + "|Grospira Peach B+\r"
	parsed := identFromString(str)
	if parsed != "Grospira Peach B+" {
		t.Errorf("Failed to parse identifier from string; got '%s'", parsed)
	}
}

func BenchmarkHL7IdentFromOBX18(b *testing.B) {
	str := okHL7Header + "OBX|" + getNRecordString(17) + "|Grospira Peach B+\r"
	for i := 0; i < b.N; i++ {
		identFromString(str)
	}
}

func TestHL7IdentFromPRT16(t *testing.T) {
	str := okHL7Header + "PRT|" + getNRecordString(15) + "|Grospira Peach B+\r"
	parsed := identFromString(str)
	if parsed != "Grospira Peach B+" {
		t.Errorf("Failed to parse identifier from string; got '%s'", parsed)
	}
}

func TestHL7IdentFromPrt16TrailingPipes(t *testing.T) {
	str := okHL7Header + "PRT|A|B|C|D|E|F|G|H|I|||||||Grospira Pluot C+||||\r"
	parsed := identFromString(str)
	if parsed != "Grospira Pluot C+" {
		t.Errorf("Failed to parse identifier from string; got '%s'", parsed)
	}
}

func BenchmarkHL7IdentFromPRT16(b *testing.B) {
	str := okHL7Header + "PRT|" + getNRecordString(15) + "|Grospira Peach B+\r"
	for i := 0; i < b.N; i++ {
		identFromString(str)
	}
}
