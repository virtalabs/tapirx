/*
Unit tests for dicom decoder
*/

package decoder

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	// import layers to run its init function
	_ "github.com/google/gopacket/layers"
)

var dicomDecoder *DicomDecoder

func init() {
	dicomDecoder = &DicomDecoder{}
	if err := dicomDecoder.Initialize(); err != nil {
		panic("Failed to initialize DICOM decoder")
	}
}

func TestDicomFile(t *testing.T) {
	testfiles, err := filepath.Glob("../testdata/dicom*.pcap")
	if err != nil {
		panic(err)
	}
	if len(testfiles) == 0 {
		panic("Couldn't find DICOM test files")
	}

	for _, testfile := range testfiles {
		if findDicomIdentifierInPcap(testfile) == "" {
			fmt.Println()
			t.Errorf("Failed to find identifier in DICOM file %s", testfile)
		}
	}
}

func findDicomIdentifierInPcap(testfile string) string {
	handle, err := pcap.OpenOffline(testfile)
	if err != nil {
		panic(err)
	}

	var identifier string
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// handlePacket(packet, stats, apiClient, nil)
		app := packet.ApplicationLayer()
		if app == nil {
			continue // Ignore packets without an application layer
		}
		decoded, _ := dicomDecoder.DecodePayload(&app)
		if decoded.Identifier != "" {
			identifier = decoded.Identifier
			break // Found an identifier in one of the packets, breaking out of the loop
		}
	}
	return identifier
}

// A "canonically good" application layer packet
var goodAppLayerBytes = []byte{
	1,           // type (Assoc Request)
	0,           // reserved (1 byte)
	0, 0, 0, 68, // length (# of bytes following)
	0, 1, // protocol version (not certain what's reasonable)
	0, 0, // reserved (2 bytes)
	// called AE title: 'bogus recipientz':
	98, 111, 103, 117, 115, 32, 114, 101, 99, 105, 112, 105, 101, 110, 116, 122,
	// calling AE title: 'bogus sender foo':
	98, 111, 103, 117, 115, 32, 115, 101, 110, 100, 101, 114, 32, 102, 111, 111,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // reserved (16 + 16 bytes)
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}

func TestDicomAppLayerGood(t *testing.T) {
	appBytes := make([]byte, len(goodAppLayerBytes))
	copy(appBytes, goodAppLayerBytes)

	appLayer := gopacket.ApplicationLayer(gopacket.Payload(appBytes))
	decoded, _ := dicomDecoder.DecodePayload(&appLayer)

	if decoded.Identifier == "" {
		t.Errorf("Failed to find identifier in payload %s", appBytes)
	}
	expectedID := "bogus sender foo"
	if decoded.Identifier != expectedID {
		t.Errorf("Bad identifier: expected '%s', got '%s'", expectedID, decoded.Identifier)
	}
}

func BenchmarkDicomDecode(b *testing.B) {
	appBytes := make([]byte, len(goodAppLayerBytes))
	copy(appBytes, goodAppLayerBytes)
	appLayer := gopacket.ApplicationLayer(gopacket.Payload(appBytes))

	for i := 0; i < b.N; i++ {
		dicomDecoder.DecodePayload(&appLayer)
	}
}

var whitespaceTests = []struct {
	callingTitle string
	expectedID   string
}{
	{"bogus sender foo", "bogus sender foo"},
	{"  foobar baz xyz", "foobar baz xyz"},
	{"foobar baz xyz  ", "foobar baz xyz"},
	{"    foobar      ", "foobar"},
}

// Offsets of interesting fields in DICOM packet structure
const offsetCallingAET = 26
const offsetCalledAET = 10
const offsetReserved32 = 42
const offsetReserved2 = 8
const offsetReserved1 = 1

func TestAETitleWhitespace(t *testing.T) {
	appBytes := make([]byte, len(goodAppLayerBytes))
	for _, tt := range whitespaceTests {
		copy(appBytes, goodAppLayerBytes)

		// Modify the 'calling AE title'
		// TODO: don't use magic number for calling title offset.
		copy(appBytes[offsetCallingAET:], []byte(tt.callingTitle))

		appLayer := gopacket.ApplicationLayer(gopacket.Payload(appBytes))
		decoded, _ := dicomDecoder.DecodePayload(&appLayer)
		if decoded.Identifier != tt.expectedID {
			t.Errorf("Bad identifier: expected '%s', got '%s'", tt.expectedID, decoded.Identifier)
		}
	}
}

var badByteTests = []struct {
	offset  int
	badByte byte
}{
	{1, 1},                     // first reserved byte
	{offsetReserved2, 1},       // reserved 2-byte
	{offsetReserved2 + 1, 1},   // --"--
	{offsetReserved32, 1},      // reserved 32-byte sequence at the end
	{offsetReserved32 + 31, 1}, //  --"--
	{5, 67},                    // length byte (decreased by 1, should fail)
	// {5, 69}, // length byte (increased by 1, would pass)
	// {3, 127}, // length byte (huge but would pass)
	{3, 128}, // length byte (too large, should fail)
	// {offsetCallingAET, 32}, // Leading space, would pass
	{offsetCallingAET, 0},  // Null byte in calling AE title: should fail
	{offsetCallingAET, 31}, // Non ISO 646-Basic byte in calling AE title: should fail
}

func TestAEBadBytes(t *testing.T) {
	appBytes := make([]byte, len(goodAppLayerBytes))
	for _, tt := range badByteTests {
		copy(appBytes, goodAppLayerBytes)

		// Modify the 'calling AE title'
		appBytes[tt.offset] = tt.badByte

		appLayer := gopacket.ApplicationLayer(gopacket.Payload(appBytes))
		decoded, _ := dicomDecoder.DecodePayload(&appLayer)
		if decoded != nil && decoded.Identifier != "" {
			t.Errorf("Bad byte '%x' in offset '%d' should have caused decoding to fail", tt.badByte, tt.offset)
		}
	}
}
