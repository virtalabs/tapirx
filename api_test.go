/*
Unit tests for API upload client.

Based on "Testing API Clients in Go"
https://www.markphelps.me/testing-api-clients-in-go/
*/
package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/virtalabs/tapirx/asset"
)

// Here we create the package scoped variables mux, server and client so that
// we can have access to them in all of our tests.
var (
	mux       *http.ServeMux
	server    *httptest.Server
	apiClient *APIClient
)

// Create an instance of httptest.Server and bind it to our mux. We’ll use the
// mux later to add Handlers.  Another thing to note is the definition of the
// setup function. This function does the work of creating the server and an
// instance of our client and also returns a function that is used to
// ‘teardown’ our server when we’re done with it. This is so each test can be
// completely independent of one another.
func setup() func() {
	mux = http.NewServeMux()
	server = httptest.NewServer(mux)

	apiURL := server.URL + "/api" // Base URL automatically chosen by httptest
	apiClient = NewAPIClient(apiURL, "", "", 1, true)

	return func() {
		server.Close()
	}
}

func TestAPISimple(t *testing.T) {
	// Make one request to the API with details for one Asset.

	// Start server and schedule stop server.  The setup() function returns a
	// function that we can in turn defer.
	teardown := setup()
	defer teardown()

	// Mock the handler for the future test request
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "Dummy message."}`))
	})

	// Make a test request
	result, err := apiClient.Upload(&asset.Asset{
		IPv4Address:    "10.0.0.1",
		IPv6Address:    "0000:0000:0000:0000:0000:FFFF:0A00:0001",
		ListensOnPort:  "8000",
		ConnectsToPort: "2575",
		MACAddress:     "11:22:33:44:55:66",
		Identifier:     "Hospira Plum A+",
		Provenance:     "HL7",
		LastSeen:       time.Time{},
		ClientID:       "ID0",
	})

	// Check output and errors
	if err != nil {
		panic(err)
	}
	if message, ok := result["message"]; !ok {
		t.Errorf("'message' key not in JSON response")
	} else if message != "Dummy message." {
		t.Errorf("'message' value in JSON response is not expected value.")
	}

}

func TestAPIThrottling(t *testing.T) {
	// Make one request to the API with details for one Asset.

	// Start server and schedule stop server.  The setup() function returns a
	// function that we can in turn defer.
	teardown := setup()
	defer teardown()

	// Mock the handler for the future test request
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "Dummy message."}`))
	})

	// Start several simultaneous uploads
	errors := make(chan error, 10)
	for i := 0; i < cap(errors); i++ {
		go func() {
			_, err := apiClient.Upload(&asset.Asset{})
			errors <- err
		}()
	}

	// Count the number of failures due to throttling
	throttlingFailures := 0
	for i := 0; i < cap(errors); i++ {
		err := <-errors
		if err != nil && err.Error() == "Ignoring API request due to throttling" {
			throttlingFailures++
		}
	}

	// Expect all uploads to fail except one
	if throttlingFailures != cap(errors)-1 {
		t.Errorf("Expected exactly 1 throttling failure")
	}
}
