// Copyright 2018 Virta Laboratories, Inc.  All rights reserved.
/*
dicom_decode: Inspect an application layer, detect if it is a DICOM
			  packet, try to extract identifier.
*/

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/google/gopacket"
	// import layers to run its init function
	_ "github.com/google/gopacket/layers"
)

// max PDU size as defined by go-netdicom
const defaultMaxPDUSize uint32 = 4 << 20

const typeAAssociateRq = 0x01

func dicomDecode(app *gopacket.ApplicationLayer) (string, string, error) {
	var appReader io.Reader = bytes.NewReader((*app).Payload())

	identifier, err := detectDicomAssociateIdentifier(appReader)

	if err != nil {
		logger.Println("Not a DICOM packet")
		return "", "", fmt.Errorf("Not a DICOM packet")
	}
	// Hard code provenance.  Note that we could add information like the HL7
	// decoder, e.g., "HL7 OBX-18" or "HL7 PRT-16"
	provenance := "DICOM"

	return identifier, provenance, nil
}

// Accept an io.Reader, detects whether it is a DICOM associate
// request.  If so, extract identifier.
func detectDicomAssociateIdentifier(in io.Reader) (string, error) {
	// The first few lines here have been lifted from
	// github.com/grailbio/go-netdicom/pdu/pdu.go::ReadPDU() .
	// They simply extract the first 6 bytes, which are
	//
	//  - 1 byte:  type
	//  - 1 byte:  reserved (0x00)
	//  - 4 bytes: PDU length (defined as the number of bytes starting with
	//             the following field and ending after a variable field
	//             that comes after the field we're extracting below.)
	var reserved [32]byte // Array to hold reserved bytes so we can fail if they're not 0x00.

	var pduType byte
	err := binary.Read(in, binary.BigEndian, &pduType)
	if err != nil {
		return "", err
	}
	// Check if the type byte corresponds to an associate request.
	//
	// The DICOM A-ASSOCIATE-RQ PDU format is defined in
	// http://dicom.nema.org/dicom/2013/output/chtml/part08/sect_9.3.html
	// Specifically, the location of the Calling Application
	// Entity Title is displayed in Fig. 9-1 and Sect. 9.3.2
	// http://dicom.nema.org/medical/dicom/current/output/chtml/part08/sect_9.3.html#figure_9-1
	// http://dicom.nema.org/medical/dicom/current/output/chtml/part08/sect_9.3.2.html
	if pduType != typeAAssociateRq {
		return "", fmt.Errorf("Type '%d' not a DICOM AAssociateRq (%d)", pduType, typeAAssociateRq)
	}

	skip := reserved[:1]
	err = binary.Read(in, binary.BigEndian, &skip)
	if err != nil {
		return "", err
	}
	if skip[0] != 0x00 {
		return "", fmt.Errorf("Reserved byte should have been 0x00, was 0x%x", skip)
	}
	if err != nil {
		return "", err
	}

	var length uint32
	err = binary.Read(in, binary.BigEndian, &length)
	if err != nil {
		return "", err
	}
	// Consider skipping the next step: "too long" will not cause us any problems
	if length >= defaultMaxPDUSize*2 {
		// Avoid using too much memory. *2 is just an arbitrary slack.
		return "", fmt.Errorf("Invalid length %d; it's much larger than max PDU size of %d", length, defaultMaxPDUSize)
	}

	// The rest of the non-variable part (for an association request)
	// should contain at least 68 bytes (as documented below), i.e.,
	// the 'length' field bust be at least 68 bytes.

	if length < 68 {
		return "", fmt.Errorf("Invalid length %d; it's not long enough to contain an association request of size 68", length)
	}

	// The next few lines will read the next 68 bytes, which are
	//
	//  -  2 bytes:  protocol version
	//  -  2 bytes:  reserved (0x00)
	//  - 16 bytes:  called Application Entity Title
	//  - 16 bytes:  calling Application Entity Title
	//  - 32 bytes:  reserved (0x00)
	var protocolVersion uint16
	err = binary.Read(in, binary.BigEndian, &protocolVersion)
	if err != nil {
		return "", err
	}
	skip2 := reserved[:2]
	err = binary.Read(in, binary.BigEndian, &skip2)
	if err != nil {
		return "", err
	}
	if skip2[0] != 0x00 {
		return "", fmt.Errorf("Reserved byte should have been 0x00, was 0x%x", skip)
	}
	if skip2[1] != 0x00 {
		return "", fmt.Errorf("Reserved byte should have been 0x00, was 0x%x", skip)
	}

	var AEArray [16]byte
	AETitle := AEArray[:]
	err = binary.Read(in, binary.BigEndian, &AETitle)
	if err != nil {
		return "", err
	}
	err = checkAEstring(&AETitle)
	if err != nil {
		return "", err
	}
	calledAETitle := strings.TrimSpace(string(AETitle))

	err = binary.Read(in, binary.BigEndian, &AETitle)
	if err != nil {
		return "", err
	}
	err = checkAEstring(&AETitle)
	if err != nil {
		return "", err
	}
	callingAETitle := strings.TrimSpace(string(AETitle))

	skip32 := reserved[:32]
	err = binary.Read(in, binary.BigEndian, &skip32)
	if err != nil {
		return "", err
	}
	for i, skip := range skip32 {
		if skip != 0x00 {
			// offset of the last 32 reserved is 42
			return "", fmt.Errorf("Reserved byte at offset %d should have been 0x00, was 0x%x",
				(i + 42), skip)
		}
	}

	if calledAETitle == "" || callingAETitle == "" {
		return "", fmt.Errorf("A_ASSOCIATE.{Called,Calling}AETitle must not be empty")
	}

	return callingAETitle, nil
}

// Check an ApplicationEntity title for validity.
// Valid characters are in the ISO646 set as documented in
// http://dicom.nema.org/medical/dicom/current/output/chtml/part08/sect_9.3.2.html
// http://dicom.nema.org/medical/dicom/current/output/chtml/part05/chapter_E.html
func checkAEstring(bytes *[]byte) error {
	for i, c := range *bytes {
		if err := checkISO646char(c); err != nil {
			return fmt.Errorf("Invalid byte '0x%x' at offset %d", c, i)
		}
	}
	return nil
}

func checkISO646char(c byte) error {
	// Characters in the range [0x20, 0x7e] == [32, 126] == [SPC, '~'] are allowed,
	// as are characters among the "special" ones listed below.
	var iso646specials = []byte{
		0x09, //  9 / TAB
		0x0a, // 10 / LF
		0x0c, // 12 / FF
		0x0d, // 13 / CR
		0x1b, // 27 / ESC
	}
	if c >= byte(' ') && c <= byte('~') {
		return nil
	}
	for _, s := range iso646specials {
		if c == s {
			return nil
		}
	}
	return fmt.Errorf("Invalid byte '0x%x'", c)
}
