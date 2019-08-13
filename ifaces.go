// Copyright 2019 Virta Laboratories, Inc.  All rights reserved.
/*
Network interface handling.
*/

package main

import (
	"fmt"
	"runtime"

	"github.com/google/gopacket/pcap"
)

// AllInterfaces returns a list of interfaces available for packet capture. Returns non-nil error if
// there is a problem fetching interface information from gopacket.pcap.
func AllInterfaces() ([]string, error) {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	ret := make([]string, len(ifaces))
	for i, iface := range ifaces {
		if runtime.GOOS == "windows" {
			// On Windows, device names are ugly, like
			// "\Device\NPF_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}",
			// so display a more descriptive name too.
			ret[i] = fmt.Sprintf("%s\t(%s)\n", iface.Name, iface.Description)
		} else {
			ret[i] = iface.Name
		}
	}

	return ret, nil
}

// ListInterfaces prints all the interfaces available for packet capture to standard
// output, one per line.
func ListInterfaces() {
	ifaces, err := AllInterfaces()
	if err != nil {
		panic(err)
	}
	for _, iface := range ifaces {
		fmt.Println(iface)
	}
}
