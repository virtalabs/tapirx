// Copyright 2018-2019 Virta Laboratories, Inc.  All rights reserved.
/*
Decoder definitions.
*/

package tapirx

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
)

// DecodingResult encodes a fact of the following kind: we saw an endpoint, possibly with a
// particular identifier, in a particular kind of network traffic at a certain moment.
type DecodingResult struct {
	Identifier string
	Provenance string
	Timestamp  time.Time
}

// PayloadDecoder defines a struct that can accept a packet payload (application layer).
type PayloadDecoder interface {
	Name() string
	Initialize() error
	DecodePayload(app *gopacket.ApplicationLayer) (*DecodingResult, error)
	String() string
}

// GenericDecoder is a decoder that does nothing.
type GenericDecoder struct {
}

// Name returns "GenericDecoder." GenericDecoder implements PayloadDecoder.
func (d *GenericDecoder) Name() string {
	return "GenericDecoder"
}

// Initialize does nothing. GenericDecoder implements PayloadDecoder.
func (d *GenericDecoder) Initialize() error {
	return nil
}

// String returns "GenericDecoder." GenericDecoder implements PayloadDecoder.
func (d *GenericDecoder) String() string {
	return d.Name()
}

// DecodePayload does nothing. GenericDecoder implements PayloadDecoder.
func (d *GenericDecoder) DecodePayload(app *gopacket.ApplicationLayer) (*DecodingResult, error) {
	payloadBytes := (*app).Payload()
	fmt.Printf("GenericDecoder got payload of %d bytes\n", len(payloadBytes))
	return &DecodingResult{}, nil
}
