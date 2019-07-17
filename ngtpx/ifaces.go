package main

import (
	"fmt"
	"runtime"

	"github.com/google/gopacket/pcap"
)

func listInterfaces() {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}

	for _, iface := range ifaces {
		if runtime.GOOS == "windows" {
			// On Windows, device names are ugly, like
			// "\Device\NPF_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}",
			// so display a more descriptive name too.
			fmt.Printf("%s\t(%s)\n", iface.Name, iface.Description)
		} else {
			fmt.Println(iface.Name)
		}
	}
}
