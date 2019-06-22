// Copyright 2018 Virta Laboratories, Inc.  All rights reserved.
/*
Track stats of packets decoded.
*/

package main

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"sort"
	"sync"
)

// Stats stores statistics about observed Assets and packets.
type Stats struct {
	sync.Mutex
	TotalPacketCount uint64            `json:"packet_count"`   // Grand total number of packets
	PacketLayers     map[string]uint64 `json:"packet_layers"`  // Count of each packet layer type
	IPv4Addresses    map[string]uint64 `json:"ipv4_addresses"` // Unique sender IPv4 addresses
	IPv6Addresses    map[string]uint64 `json:"ipv6_addresses"` // Unique sender IPv6 addresses
	Ports            map[string]uint64 `json:"ports"`          // Unique sender TCP ports
	MACs             map[string]uint64 `json:"mac_addresses"`  // Unique sender MAC addresses
	Identifiers      map[string]uint64 `json:"identifiers"`    // Unique device identification strings
	Provenances      map[string]uint64 `json:"provenances"`    // Count of identifier provenance
	Errors           map[string]uint64 `json:"errors"`         // Count of errors
	UploadResults    map[string]uint64 `json:"uploads"`        // Count upload outcodes
}

// NewStats returns a new, empty container for statistics.
func NewStats() *Stats {
	s := new(Stats)
	s.PacketLayers = make(map[string]uint64)
	s.IPv4Addresses = make(map[string]uint64)
	s.IPv6Addresses = make(map[string]uint64)
	s.Ports = make(map[string]uint64)
	s.MACs = make(map[string]uint64)
	s.Identifiers = make(map[string]uint64)
	s.Provenances = make(map[string]uint64)
	s.Errors = make(map[string]uint64)
	s.UploadResults = make(map[string]uint64)
	return s
}

// AddLayer tracks the number of each type of packet layer
func (s *Stats) AddLayer(layerName string) {
	s.Lock()
	defer s.Unlock()
	s.PacketLayers[layerName]++
}

// AddPacket updates the packet count.
func (s *Stats) AddPacket() {
	s.Lock()
	defer s.Unlock()
	s.TotalPacketCount++
}

// AddError tracks the number of each type of error
func (s *Stats) AddError(err error) {
	s.Lock()
	defer s.Unlock()
	s.Errors[err.Error()]++
}

// AddAsset reports that a valid packet with identifying information has been
// seen.
func (s *Stats) AddAsset(asset *Asset) {
	log.Println("AddAsset()")
	s.Lock()
	defer s.Unlock()
	if asset.IPv4Address != "" {
		s.IPv4Addresses[asset.IPv4Address]++
	}
	if asset.IPv6Address != "" {
		s.IPv6Addresses[asset.IPv6Address]++
	}
	if asset.ListensOnPort != "" {
		s.Ports[asset.ListensOnPort]++
	}
	if asset.ConnectsToPort != "" {
		s.Ports[asset.ConnectsToPort]++
	}
	if asset.MACAddress != "" {
		s.MACs[asset.MACAddress]++
	}
	if asset.Identifier != "" {
		s.Identifiers[asset.Identifier]++
	}
	if asset.Provenance != "" {
		s.Provenances[asset.Provenance]++
	}
}

// AddUpload reports that an API upload succeeded.
func (s *Stats) AddUpload() {
	s.Lock()
	defer s.Unlock()
	s.UploadResults["OK"]++
}

// AddUploadError reports that an API upload succeeded.
func (s *Stats) AddUploadError(err error) {
	s.Lock()
	defer s.Unlock()
	s.UploadResults[err.Error()]++
}

func sortedMapKeys(m map[string]uint64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (s *Stats) String() string {
	statJSON, _ := json.MarshalIndent(s, "", "  ")
	return string(statJSON)
}
