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
	// "fknsrs.biz/p/hl7"
	"fmt"

	"strings"

	"github.com/google/gopacket"
	// import layers to run its init function
	_ "github.com/google/gopacket/layers"

	"github.com/virtalabs/hl7"
)

// Compile queries we'll later use on HL7 messages
var prt10Query, _ = hl7.ParseQuery("PRT-10")
var obx18Query, _ = hl7.ParseQuery("OBX-18")

// Inspect an application layer, determine if it is an HL7 packet, try to
// extract identifier.  Returns identifier, provenance, error.
func hl7Decode(app *gopacket.ApplicationLayer) (string, string, error) {
	// An HL7 payload starts with "MSH",which stands for "Message Header".
	// Sometimes, messages are preceded by '\v'.

	// Messages that start with "MSH" immediately
	payloadBytes := (*app).Payload()
	payloadStr := string((*app).Payload())
	if len(payloadStr) >= 3 && strings.HasPrefix(payloadStr, "MSH") {
		// DO nothing
	} else if len(payloadStr) >= 4 && strings.HasSuffix(payloadStr[:4], "MSH") {
		// Payload starts at index 1 (not 0)
		payloadBytes = payloadBytes[1:]
		payloadStr = payloadStr[1:]
	} else {
		// Ignore messages that don't start with "MSH"
		return "", "", fmt.Errorf("Not an HL7 packet")
	}
	logger.Println("Found HL7 header")

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
	// logger.Printf("%+q\n", string(app.Payload()))
	logger.Println("  HL7 PAYLOAD")
	for _, segment := range strings.Split(payloadStr, "\r") {
		logger.Printf("    %+q\n", segment)
	}

	// Parse HL7 payload
	var message hl7.Message
	message, _, err := hl7.ParseMessage(payloadBytes)
	if err != nil {
		logger.Println("Error parsing HL7 payload")
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
	if prt10 := prt10Query.GetString(message); prt10 != "" {
		// Found in PRT segment
		logger.Println("  Found HL7 identifier in PRT-10 segment")
		identifier = prt10
		provenance = "HL7 PRT-10"
	} else if obx18 := obx18Query.GetString(message); obx18 != "" {
		// Did not find identifier in PRT segment, trying for OBX-18 field of the
		// OBX segment, which from V2.7 of HL7 is retained for backward
		// compatibility only.
		logger.Println("  Found HL7 identifier in OBX-18 segment")
		identifier = obx18
		provenance = "HL7 OBX-18"
	}

	if identifier == "" {
		// FIXME should this be an error?
		logger.Println("  HL7 (no identifier)")
	} else {
		// Report to logs
		logger.Printf("  HL7 identifier: %s\n", identifier)
	}

	return identifier, provenance, nil
}
