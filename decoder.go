// Copyright 2018-2019 Virta Laboratories, Inc.  All rights reserved.
/*
Decoder definitions.
*/

package main

import "github.com/google/gopacket"

// PayloadDecoder defines a struct that can accept a packet payload (application layer).
type PayloadDecoder interface {
	Name() string
	Initialize() error
	Wants(app *gopacket.ApplicationLayer) bool
	DecodePayload(app *gopacket.ApplicationLayer) (string, string, error)
	String() string
}
