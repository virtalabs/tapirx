/*
Unit tests for Asset functions.
*/
package main

import (
	"io/ioutil"
	"os"
	"testing"
	"time"
)

// Write a file and read it.
//
//FIXME this really should use a "stringstream" approach instead of writing a
//real file.
func TestAssetCSV(t *testing.T) {
	asset := &Asset{
		"10.0.0.1",
		"0000:0000:0000:0000:0000:FFFF:0A00:0001",
		"8000",
		"10.1.2.3",
		"2575",
		"11:22:33:44:55:66",
		"Hospira Plum A+",
		"HL7",
		time.Time{},
		"ID0",
	}

	// Write file
	w, err := NewAssetCSVWriter("out.csv")
	defer os.Remove("out.csv")
	if err != nil {
		panic(err)
	}
	w.Append(asset)
	w.Append(asset)
	w.Close()

	// Read file
	actual, err := ioutil.ReadFile("out.csv")
	if err != nil {
		panic(err)
	}
	expected := `ipv4_address,ipv6_address,open_port_tcp,connect_port_tcp,mac_address,identifier,provenance,last_seen,client_id
10.0.0.1,0000:0000:0000:0000:0000:FFFF:0A00:0001,2575,11:22:33:44:55:66,Hospira Plum A+,HL7,0001-01-01 00:00:00 +0000 UTC,ID0
10.0.0.1,0000:0000:0000:0000:0000:FFFF:0A00:0001,2575,11:22:33:44:55:66,Hospira Plum A+,HL7,0001-01-01 00:00:00 +0000 UTC,ID0
`
	if string(actual) != expected {
		t.Errorf("CSV file actual %s does not match expected: %s\n", actual, expected)
	}
}
