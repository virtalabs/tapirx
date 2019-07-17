/*
Unit tests for stats functions.
*/
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/virtalabs/tapirx/asset"
)

func TestStatsString(t *testing.T) {
	// Stringify a stats object
	testIP := "10.0.0.1"
	testMAC := "11:22:33:44:55:66"

	stats := NewStats()
	stats.AddError(fmt.Errorf("No application layer"))
	stats.AddError(fmt.Errorf("No identifier"))
	stats.AddAsset(&asset.Asset{
		IPv4Address:    testIP,
		IPv6Address:    "0000:0000:0000:0000:0000:FFFF:0A00:0001",
		ListensOnPort:  "8000",
		ConnectsToPort: "2575",
		MACAddress:     testMAC,
		Identifier:     "Hospira Plum A+",
		Provenance:     "HL7",
		LastSeen:       time.Time{},
		ClientID:       "ID0",
	})
	stats.AddUpload()
	stats.AddUploadError(fmt.Errorf("Error making request"))

	var resultStats Stats
	if err := json.Unmarshal([]byte(stats.String()), &resultStats); err != nil {
		t.Error(err)
	}

	if resultStats.TotalPacketCount != stats.TotalPacketCount {
		t.Errorf("Incorrect TotalPacketCount")
	}
	if len(resultStats.IPv4Addresses) != 1 {
		t.Errorf("Incorrect IPv4Addresses")
	}
	if resultStats.IPv4Addresses[testIP] != 1 {
		t.Errorf("Wrong IP count for %s", testIP)
	}
	if len(resultStats.IPv6Addresses) != 1 {
		t.Errorf("Incorrect IPv6Addresses")
	}
	if len(resultStats.Ports) != 2 {
		t.Errorf("Incorrect Ports")
	}
	if len(resultStats.MACs) != 1 {
		t.Errorf("Incorrect MACs")
	}
	if resultStats.MACs[testMAC] != 1 {
		t.Errorf("Wrong MAC count for %s", testMAC)
	}
	if len(resultStats.Identifiers) != 1 {
		t.Errorf("Incorrect Identifiers")
	}
	if len(resultStats.Provenances) != 1 {
		t.Errorf("Incorrect Provenances")
	}
	if len(resultStats.UploadResults) != 2 {
		t.Errorf("Incorrect UploadResults")
	}
	if len(resultStats.Errors) != 2 {
		t.Errorf("Incorrect Errors")
	}
}

func TestStatsSameID(t *testing.T) {
	// Two different devices with the same identifier, but different network data.
	stats := NewStats()
	stats.AddPacket()
	stats.AddAsset(&asset.Asset{
		IPv4Address:    "10.0.0.1",
		IPv6Address:    "0000:0000:0000:0000:0000:FFFF:0A00:0001",
		ListensOnPort:  "8000",
		ConnectsToPort: "2575",
		MACAddress:     "11:22:33:44:55:66",
		Identifier:     "Hospira Plum A+",
		Provenance:     "HL7",
		LastSeen:       time.Time{},
		ClientID:       "ID0",
	})
	stats.AddPacket()
	stats.AddAsset(&asset.Asset{
		IPv4Address:    "10.0.0.2",
		IPv6Address:    "0000:0000:0000:0000:0000:FFFF:0A00:0002",
		ListensOnPort:  "8000",
		ConnectsToPort: "2575",
		MACAddress:     "11:22:33:44:55:67",
		Identifier:     "Hospira Plum A+",
		Provenance:     "HL7",
		LastSeen:       time.Time{},
		ClientID:       "ID0",
	})
	if stats.TotalPacketCount != 2 {
		t.Errorf("Expected 2 total packets")
	}
	if stats.Provenances["HL7"] != 2 {
		t.Errorf("Expected 2 HL7 packets")
	}
	if len(stats.MACs) != 2 {
		t.Errorf("Expected 2 unique send MAC addresses")
	}
	if len(stats.IPv4Addresses) != 2 {
		t.Errorf("Expected 2 unique ipv4 addresses")
	}
	if len(stats.IPv6Addresses) != 2 {
		t.Errorf("Expected 2 unique ipv6 addresses")
	}
	if len(stats.Ports) != 2 {
		t.Errorf("Expected 2 unique ports")
	}
	if len(stats.Identifiers) != 1 {
		t.Errorf("Expected 1 unique identifier")
	}
}

func TestStatsDifferentID(t *testing.T) {
	// Two different devices with different identifiers and network data
	stats := NewStats()
	stats.AddPacket()
	stats.AddAsset(&asset.Asset{
		IPv4Address:    "10.0.0.1",
		IPv6Address:    "0000:0000:0000:0000:0000:FFFF:0A00:0001",
		ListensOnPort:  "8000",
		ConnectsToPort: "2575",
		MACAddress:     "11:22:33:44:55:66",
		Identifier:     "Hospira Plum A+",
		Provenance:     "HL7",
		LastSeen:       time.Time{},
		ClientID:       "ID0",
	})
	stats.AddPacket()
	stats.AddAsset(&asset.Asset{
		IPv4Address:    "10.0.0.2",
		IPv6Address:    "0000:0000:0000:0000:0000:FFFF:0A00:0002",
		ListensOnPort:  "9000",
		ConnectsToPort: "2575",
		MACAddress:     "11:22:33:44:55:67",
		Identifier:     "Alaris 8000",
		Provenance:     "HL7",
		LastSeen:       time.Time{},
		ClientID:       "ID0",
	})
	if stats.TotalPacketCount != 2 {
		t.Errorf("Expected 2 total packets")
	}
	if stats.Provenances["HL7"] != 2 {
		t.Errorf("Expected 2 HL7 packets")
	}
	if len(stats.MACs) != 2 {
		t.Errorf("Expected 2 unique send MAC addresses")
	}
	if len(stats.IPv4Addresses) != 2 {
		t.Errorf("Expected 2 unique ipv4 addresses")
	}
	if len(stats.IPv6Addresses) != 2 {
		t.Errorf("Expected 2 unique ipv6 addresses")
	}
	if len(stats.Ports) != 3 {
		t.Errorf("Expected 3 unique send ports")
	}
	if len(stats.Identifiers) != 2 {
		t.Errorf("Expected 1 unique identifier")
	}
}

func TestStatsSameEverything(t *testing.T) {
	// Two observations from the same device.
	stats := NewStats()
	stats.AddPacket()
	stats.AddAsset(&asset.Asset{
		IPv4Address:    "10.0.0.1",
		IPv6Address:    "0000:0000:0000:0000:0000:FFFF:0A00:0001",
		ListensOnPort:  "8000",
		ConnectsToPort: "2575",
		MACAddress:     "11:22:33:44:55:66",
		Identifier:     "Hospira Plum A+",
		Provenance:     "HL7",
		LastSeen:       time.Time{},
		ClientID:       "ID0",
	})
	stats.AddPacket()
	stats.AddAsset(&asset.Asset{
		IPv4Address:    "10.0.0.1",
		IPv6Address:    "0000:0000:0000:0000:0000:FFFF:0A00:0001",
		ListensOnPort:  "8000",
		ConnectsToPort: "2575",
		MACAddress:     "11:22:33:44:55:66",
		Identifier:     "Hospira Plum A+",
		Provenance:     "HL7",
		LastSeen:       time.Time{},
		ClientID:       "ID0",
	})
	if stats.TotalPacketCount != 2 {
		t.Errorf("Expected 2 total packets")
	}
	if stats.Provenances["HL7"] != 2 {
		t.Errorf("Expected 2 HL7 packets")
	}
	if len(stats.MACs) != 1 {
		t.Errorf("Expected 2 unique send MAC addresses")
	}
	if len(stats.IPv4Addresses) != 1 {
		t.Errorf("Expected 2 unique ipv4 addresses")
	}
	if len(stats.IPv6Addresses) != 1 {
		t.Errorf("Expected 2 unique ipv6 addresses")
	}
	if len(stats.Ports) != 2 {
		t.Errorf("Expected 2 unique send ports")
	}
	if len(stats.Identifiers) != 1 {
		t.Errorf("Expected 1 unique identifier")
	}
}

func TestAddError(t *testing.T) {
	stats := NewStats()
	errStr := "A strange error string"
	stats.AddError(errors.New(errStr))

	if len(stats.Errors) != 1 {
		t.Errorf("Stats did not correctly record exactly one error")
	}

	for key := range stats.Errors {
		if key != errStr {
			t.Errorf("Stats stored the wrong key")
		}
	}
}
