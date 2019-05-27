// Copyright 2018-2019 Virta Laboratories, Inc.  All rights reserved.
/*
Decoder definitions.
*/

package decoder

import "github.com/google/gopacket"

// PayloadDecoder defines a struct that can accept a packet payload (application layer).
type PayloadDecoder interface {
	Name() string
	Initialize() error
	DecodePayload(app *gopacket.ApplicationLayer) (string, string, error)
	String() string
}
