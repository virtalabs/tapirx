package main

import (
	"net"
	"testing"
)

func TestArpTableAdd(t *testing.T) {
	arpTable := NewArpTable(0)

	arpTable.Add(net.HardwareAddr{1, 2, 3, 4, 5, 6}, net.IP{10, 1, 2, 3})
	if len(arpTable.arpTable) != 1 {
		t.Error("Failed to add entry")
	}
	arpTable.Add(net.HardwareAddr{1, 2, 3, 4, 5, 6}, net.IP{10, 1, 2, 3})
	if len(arpTable.arpTable) != 1 {
		t.Error("Should have overwritten existing entry")
	}
}

func BenchmarkArpTableAdd(b *testing.B) {
	arpTable := NewArpTable(0)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			arpTable.Add(net.HardwareAddr{1, 2, 3, 4, 5, 6}, net.IP{10, 1, 2, 3})
		}
	})
}
