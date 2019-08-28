// Copyright 2018-2019 Virta Laboratories, Inc.  All rights reserved.
/*
hl7_decode: Inspect an application layer, detect if it is an HL7
			packet, try to extract identifier.

This module will make a lot more sense with an understanding of the HL7
specification, which is long and boring.  A quick overview is at
https://www.fknsrs.biz/blog/golang-hl7-library.html.
*/

package tapirx

import (
	"bytes"
	"fmt"
	"log"
	"time"

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
	Logger *log.Logger
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

// DecodePayload extracts device identifiers from an application-layer payload. Returns a nil
// *DecodingResult if there was nothing meaningful to extract.
func (decoder *HL7Decoder) DecodePayload(app *gopacket.ApplicationLayer) (*DecodingResult, error) {
	payloadBytes := (*app).Payload()
	if len(payloadBytes) < 3 {
		return nil, fmt.Errorf("Not an HL7 packet (too small)")
	}
	if bytes.Compare(mshHeader, payloadBytes[:3]) == 0 {
		// Found header, do nothing
	} else if bytes.Compare(mshHeader, payloadBytes[1:4]) == 0 {
		payloadBytes = payloadBytes[1:]
	} else {
		// Ignore messages that don't start with "MSH"
		return nil, fmt.Errorf("Not an HL7 packet (no header)")
	}

	// Parse HL7 payload
	var message hl7.Message
	message, _, err := hl7.ParseMessage(payloadBytes)
	if err != nil {
		return nil, err
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
			identifier = strings.Trim(ident, " \t")
			provenance = "HL7 " + query.hl7Field
			break
		}
	}

	result := &DecodingResult{
		Identifier: identifier,
		Provenance: provenance,
		Timestamp:  time.Now(),
	}
	return result, nil
}
