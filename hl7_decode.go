// Copyright 2018-2019 Virta Laboratories, Inc.  All rights reserved.
/*
hl7_decode: Inspect an application layer, detect if it is an HL7
			packet, try to extract identifier.

This module will make a lot more sense with an understanding of the HL7
specification, which is long and boring.  A quick overview is at
https://www.fknsrs.biz/blog/golang-hl7-library.html.
*/

package main

import (
	"bytes"
	"fmt"
	log "github.com/sirupsen/logrus"

	"strings"

	"github.com/google/gopacket"
	// import layers to run its init function
	_ "github.com/google/gopacket/layers"

	// Mirror of "fknsrs.biz/p/hl7"
	"github.com/virtalabs/hl7"
)

// HL7Query represents a compiled query and its corresponding output field.
type HL7Query struct {
	hl7Field    string
	hl7Query    *hl7.Query
	outputField string
}

// CompileQuery compiles an HL7 field query into an HL7Query.
func (q *HL7Query) CompileQuery() error {
	qry, err := hl7.ParseQuery(q.hl7Field)
	if err != nil {
		return err
	}
	q.hl7Query = qry
	return nil
}

func (q HL7Query) String() string {
	compiled := q.hl7Query != nil
	return fmt.Sprintf("HL7Query{%v -> %v, %v}", q.hl7Field, q.outputField, compiled)
}

var mshHeader = []byte{77, 83, 72} // "MSH"

// HL7Decoder receives application-layer payloads and, when possible, extracts
// identifying information from HL7 messages therein.
type HL7Decoder struct {
	// Compiled HL7 queries to be matched against
	hl7Queries []HL7Query
}

// Name returns the name of the decoder.
func (decoder HL7Decoder) Name() string {
	return "HL7"
}

func (decoder HL7Decoder) String() string {
	decoderNames := make([]string, len(decoder.hl7Queries))
	for i, q := range decoder.hl7Queries {
		decoderNames[i] = q.String()
	}
	return fmt.Sprintf("%s(%s)",
		decoder.Name(),
		strings.Join(decoderNames, ","))
}

// AddField registers an additional field matcher with an HL7Decoder.
//
// TODO: make outputName actually do something
func (decoder *HL7Decoder) AddField(fieldName, outputName string) error {
	newQuery := HL7Query{hl7Field: fieldName, outputField: outputName}
	if err := newQuery.CompileQuery(); err != nil {
		return err
	}
	decoder.hl7Queries = append(decoder.hl7Queries, newQuery)
	return nil
}

// Initialize precompiles a set of HL7 queries to match against payloads.
//
// Currently uses a hard-coded set of "interesting" fields.
func (decoder *HL7Decoder) Initialize() error {
	placeholder := "" // TODO: use meaningful output field names
	if err := decoder.AddField("PRT-16", placeholder); err != nil {
		return err
	}
	if err := decoder.AddField("OBX-18", placeholder); err != nil {
		return err
	}
	return nil
}

// DecodePayload extracts device identifiers from an application-layer payload.
func (decoder *HL7Decoder) DecodePayload(app *gopacket.ApplicationLayer) (string, string, error) {
	payloadBytes := (*app).Payload()
	if len(payloadBytes) < 3 {
		return "", "", fmt.Errorf("Not an HL7 packet (too small)")
	}
	if bytes.Compare(mshHeader, payloadBytes[:3]) == 0 {
		// Found header, do nothing
	} else if bytes.Compare(mshHeader, payloadBytes[1:4]) == 0 {
		payloadBytes = payloadBytes[1:]
	} else {
		// Ignore messages that don't start with "MSH"
		return "", "", fmt.Errorf("Not an HL7 packet (no header)")
	}
	log.Debug("Found HL7 header")

	// Print HL7 payload
	//
	// "%+q", from the docs: If we are unfamiliar or confused by strange values
	// in the string, we can use the "plus" flag to the %q verb. This flag
	// causes the output to escape not only non-printable sequences, but also
	// any non-ASCII bytes, all while interpreting UTF-8. The result is that it
	// exposes the Unicode values of properly formatted UTF-8 that represents
	// non-ASCII data in the string:
	//
	// Print a raw Payload with escaped non-ASCII printing characters:
	// log.Printf("%+q\n", string(app.Payload()))
	payloadStr := string(payloadBytes)
	log.Debug("  HL7 PAYLOAD")
	for _, segment := range strings.Split(payloadStr, "\r") {
		log.Debug("    %+q", segment)
	}

	// Parse HL7 payload
	var message hl7.Message
	message, _, err := hl7.ParseMessage(payloadBytes)
	if err != nil {
		log.Warn("Error parsing HL7 payload")
		return "", "", err
	}

	// Parse identifiers
	//
	// HL7 (V2.8) supports FDA UDI (Unique Device Identifier) by allowing both
	// the full label text in PRT-10 and the components in PRT-16 through PRT22
	//
	// PRT-10 Full text label for FDA-UDI (string)
	// PRT-16 Participation Device Identifier (string)
	// PRT-17 Participation Device Manufacture Date (Date-string?)
	// PRT-18 Participation Device Expiry Date (Date-string?)
	// PRT-19 Participation Device Lot Number (String)
	// PRT-20 Participation Device Serial Number (String)
	// PRT-21 Participation Device Donation Identification (String) - relates to donation of blood etc
	// PRT-22 Participation Device Type (string)
	//
	// Reference:
	// https://www.hl7.org/documentcenter/public/wg/healthcaredevices/IEEE_UDI.ppt
	//
	// Reference:
	// https://wiki.ihe.net/images/6/6c/UDITopic.pdf
	var identifier, provenance string

	for _, query := range decoder.hl7Queries {
		if ident := query.hl7Query.GetString(message); ident != "" {
			log.Debugf("  Found HL7 identifier in %s segment", query.hl7Field)
			identifier = ident
			provenance = "HL7 " + query.hl7Field
			break
		}
	}

	log.Debug("  HL7 identifier: [%s] (provenance: %s)", identifier, provenance)

	return identifier, provenance, nil
}
