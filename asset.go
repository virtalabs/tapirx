package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// NewAsset creates an Asset with safe defaults (e.g., empty slice instead of nil
// for ListensOnPorts so it serializes as [] rather than null in JSON).
func NewAsset() *Asset {
	return &Asset{
		ListensOnPorts: []int{},
	}
}

// An Asset represents an observation of one endpoint seen in network traffic.
//
// Each field is annotated with its JSON field name.
type Asset struct {
	IPv4Address    string    `json:"ip_address"`
	IPv6Address    string    `json:"ipv6_address"`
	ListensOnPorts []int     `json:"open_ports_tcp"`
	ConnectsToPort string    `json:"connect_port_tcp"`
	MACAddress     string    `json:"mac_address"`
	Identifier     string    `json:"name"`
	Provenance     string    `json:"provenance"`
	LastSeen       time.Time `json:"last_seen"`
	ClientID       string    `json:"client_id"`
}

// AssetCSVWriter contains the state needed to write to a CSV file
type AssetCSVWriter struct {
	sync.Mutex
	filename   string
	filehandle *os.File
	csvWriter  *csv.Writer
}

// NewAssetCSVWriter creates (or overwrites) a file and writes a CSV header.
//
// If filename is "-", write to standard output instead of a file.
func NewAssetCSVWriter(filename string) (*AssetCSVWriter, error) {
	// For testing
	if filename == "" {
		return nil, nil
	}

	w := new(AssetCSVWriter)
	w.filename = filename
	if w.filename == "-" {
		w.filehandle = os.Stdout
	} else {
		file, err := os.OpenFile(w.filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		w.filehandle = file
	}
	w.csvWriter = csv.NewWriter(w.filehandle)

	// Write CSV header
	header := []string{
		"ip_address",
		"ipv6_address",
		"open_ports_tcp",
		"connect_port_tcp",
		"mac_address",
		"name",
		"provenance",
		"last_seen",
		"client_id",
	}
	if err := w.csvWriter.Write(header); err != nil {
		return nil, err
	}

	// Flush buffer to file
	w.csvWriter.Flush()
	if err := w.csvWriter.Error(); err != nil {
		return nil, err
	}
	return w, nil
}

// Enabled returns true if the writer is enabled
func (w *AssetCSVWriter) Enabled() bool {
	return w.filename != ""
}

// Close closes the CSV writer's underlyingfilehandle.
func (w *AssetCSVWriter) Close() {
	w.Lock()
	defer w.Unlock()
	w.filehandle.Close()
}

// Append appends one Asset to a file in CSV format.
func (w *AssetCSVWriter) Append(asset *Asset) error {
	w.Lock()
	defer w.Unlock()

	// Write CSV row
	ports := make([]string, len(asset.ListensOnPorts))
	for i, p := range asset.ListensOnPorts {
		ports[i] = fmt.Sprintf("%d", p)
	}
	row := []string{
		asset.IPv4Address,
		asset.IPv6Address,
		strings.Join(ports, ";"),
		asset.ConnectsToPort,
		asset.MACAddress,
		asset.Identifier,
		asset.Provenance,
		asset.LastSeen.String(),
		asset.ClientID,
	}
	if err := w.csvWriter.Write(row); err != nil {
		return err
	}

	// Flush buffer to file
	w.csvWriter.Flush()
	return w.csvWriter.Error() // may be nil
}
