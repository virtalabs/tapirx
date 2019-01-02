/*
Unit tests for main command line interface.
*/
package main

import "testing"
import "os"

func TestMainSimple(t *testing.T) {
	// Save and restore the "real" args, which might have been passed to the
	// "go test" execution.  I'm mimicing testing code from the flag library.
	// https://golang.org/src/flag/flag_test.go#L318
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"cmd", "-pcap=testdata/HL7-ADT-UDI-OBX.pcap"}
	main()
}
