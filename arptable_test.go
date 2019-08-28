package tapirx

import (
	"net"
	"testing"
	"time"
)

func TestArpTableAdd(t *testing.T) {
	arpTable := NewArpTable(0, 0)

	arpTable.Add(net.HardwareAddr{1, 2, 3, 4, 5, 6}, net.IP{10, 1, 2, 3})
	if len(arpTable.arpTable) != 1 {
		t.Error("Failed to add entry")
	}
	arpTable.Add(net.HardwareAddr{1, 2, 3, 4, 5, 6}, net.IP{10, 1, 2, 3})
	if len(arpTable.arpTable) != 1 {
		t.Error("Should have overwritten existing entry")
	}
}

func TestArpTableExpire(t *testing.T) {
	arpTable := NewArpTable(200*time.Millisecond, 50*time.Millisecond)
	arpTable.Add(net.HardwareAddr{1, 2, 3, 4, 5, 6}, net.IP{10, 1, 2, 3})

	// sleep long enough to expire the entry
	time.Sleep(300 * time.Millisecond)
	if arpTable.Length() > 0 {
		t.Error("ARP table entry should have been expired")
	}
}

func BenchmarkArpTableAdd(b *testing.B) {
	arpTable := NewArpTable(0, 0)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			arpTable.Add(net.HardwareAddr{1, 2, 3, 4, 5, 6}, net.IP{10, 1, 2, 3})
		}
	})
}
