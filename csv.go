// Copyright 2019 Virta Laboratories, Inc.  All rights reserved.
/*
Functions for emitting asset information.
*/

package tapirx

import (
	"encoding/csv"
	"log"
	"os"
	"sync"
)

// CSVEmitter is an Emitter that outputs Asset information to a CSV file.
type CSVEmitter struct {
	sync.Mutex
	Filename string
	fh       *os.File
	csvw     *csv.Writer
}

// NewCSVEmitter creates a new CSVEmitter that outputs to a file or standard output.
func NewCSVEmitter(filename string) (*CSVEmitter, error) {
	e := &CSVEmitter{Filename: filename}
	if e.Filename == "-" {
		e.fh = os.Stdout
	} else {
		fh, err := os.OpenFile(e.Filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		e.fh = fh
	}
	e.csvw = csv.NewWriter(e.fh)
	return e, nil
}

// Emit appends an asset to the CSV output.
func (c *CSVEmitter) Emit(asset *Asset) error {
	// TODO(ransford): write me
	c.csvw.Write([]string{
		asset.MACAddress,
		asset.IPv4Address,
		asset.IPv6Address,
		asset.Identifier,
		asset.LastSeen.String(),
		asset.Provenance,
	})
	return nil
}

// EmitSet emits a set of assets to the CSV output.
func (c *CSVEmitter) EmitSet(as *AssetSet) error {
	as.Lock()
	defer as.Unlock()
	log.Printf("Emitting %d assets.\n", len(as.Assets))
	for _, asset := range as.Assets {
		if err := c.Emit(asset); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the CSV output.
func (c *CSVEmitter) Close() error {
	return c.fh.Close()
}
