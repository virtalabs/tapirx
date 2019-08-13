// Copyright 2019 Virta Laboratories, Inc.  All rights reserved.
/*
ARP table data structures and functions.
*/

package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// ArpTableEntry holds ARP table entries, including a timestamp that is optionally used for
// expiration.
type ArpTableEntry struct {
	MAC   net.HardwareAddr
	IP    net.IP
	Added time.Time
}

// ArpTable represents an ARP table, i.e., a mapping of hardware MAC addresses to IP addresses.
type ArpTable struct {
	sync.Mutex
	arpTable       map[string]ArpTableEntry
	MaxAge         time.Duration
	ExpireInterval time.Duration
}

// Add adds or overwrites an ARP table entry. If the hardware address hwAddr already exists in the
// ARP table, the associated IP address information will be replaced with the provided ip (even if
// it is the same as the existing entry) and its timestamp will be updated.
func (a *ArpTable) Add(hwAddr net.HardwareAddr, ip net.IP) {
	a.Lock()
	a.arpTable[string(hwAddr)] = ArpTableEntry{hwAddr, ip, time.Now()}
	a.Unlock()
}

// Length returns the number of entries (the number of distinct hardware addresses) in the ARP table
func (a *ArpTable) Length() int {
	return len(a.arpTable)
}

// Print prints the ARP table.
func (a *ArpTable) String() string {
	var sb strings.Builder
	sb.WriteString("ArpTable{")
	for mac, entry := range a.arpTable {
		sb.WriteString(fmt.Sprintf(" %v -> %v,",
			net.HardwareAddr([]byte(mac)),
			net.IP(entry.IP)))
	}
	sb.WriteString("}")
	return sb.String()
}

// NewArpTable initializes an ARP table. If maxAge is not zero, ARP table entries older than maxAge
// will be removed every expireInterval.
func NewArpTable(maxAge time.Duration, expireInterval time.Duration) *ArpTable {
	at := &ArpTable{}
	at.arpTable = make(map[string]ArpTableEntry)
	at.MaxAge = maxAge
	at.ExpireInterval = expireInterval

	if at.MaxAge > 0 {
		go func() {
			timer := time.NewTicker(expireInterval)
			for range timer.C {
				if n := at.RemoveExpired(); n > 0 {
					log.Printf("Expired %d ARP table entries.\n", n)
				}
			}
		}()
	}

	return at
}

// RemoveExpired removes ARP table entries that are older than a.MaxAge and returns the number of
// entries it removed.
func (a *ArpTable) RemoveExpired() uint {
	a.Lock()
	defer a.Unlock()

	var expired uint
	for mac, ent := range a.arpTable {
		if time.Since(ent.Added) > a.MaxAge {
			delete(a.arpTable, mac)
			expired++
		}
	}
	return expired
}
