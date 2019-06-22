// Copyright 2018-2019 Virta Laboratories, Inc.  All rights reserved.
/*
Decoder definitions.
*/

package decoder

import (
	"log"

	"github.com/google/gopacket"
)

// PayloadDecoder defines a struct that can accept a packet payload (application layer).
type PayloadDecoder interface {
	Name() string
	Initialize() error
	DecodePayload(app *gopacket.ApplicationLayer) (string, string, error)
	String() string
}

type GenericDecoder struct {
	Logger *log.Logger
}

func (d *GenericDecoder) Name() string {
	return "GenericDecoder"
}

func (d *GenericDecoder) Initialize() error {
	return nil
}

func (d *GenericDecoder) String() string {
	return d.Name()
}

func (d *GenericDecoder) DecodePayload(app *gopacket.ApplicationLayer) (string, string, error) {
	payloadBytes := (*app).Payload()
	d.Logger.Printf("GenericDecoder: payload of %d bytes\n", len(payloadBytes))
	return "a thing", "another thing", nil
}
