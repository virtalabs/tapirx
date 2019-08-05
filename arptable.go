package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

// ArpTable represents an ARP table, i.e., a mapping of hardware MAC addresses to IP addresses.
type ArpTable struct {
	sync.Mutex
	arpTable map[string]net.IP
}

// Add adds an ARP table entry.
func (a *ArpTable) Add(hwAddr net.HardwareAddr, ip net.IP) {
	a.Lock()
	a.arpTable[string(hwAddr)] = ip
	a.Unlock()
}

// Print prints the ARP table.
func (a *ArpTable) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("ARP table (%d): ", len(a.arpTable)))
	for mac, ip := range a.arpTable {
		sb.WriteString(fmt.Sprintf(" - %v == %v; ",
			net.HardwareAddr([]byte(mac)),
			net.IP(ip)))
	}
	return sb.String()
}

// NewArpTable initialized an ARP table.
func NewArpTable() *ArpTable {
	at := &ArpTable{}
	at.arpTable = make(map[string]net.IP)
	return at
}
