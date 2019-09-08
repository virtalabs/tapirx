// Copyright 2019 Virta Laboratories, Inc.  All rights reserved.
/*
Submit information about discovered devices to other services via REST API
endpoints.

Upon discovering and/or identifying a device, submit a POST request to a URL
like https://my-other-system.com/device/, optionally presenting an authorization
token.  This API endpoint should behave like an "upsert" request, i.e., it
should update itself rather than bail when it receives a clue about a device it
has been told about before.

Concurrent requests to this API endpoint are limited according to the apiLimit
parameter of NewAPIClient(). If apiLimit number of requests are currently in
flight, requests will be canceled until there are slots available.

Helpful documentation about requests in Go:
- https://golang.org/pkg/net/http/
- http://polyglot.ninja/golang-making-http-requests/
*/

package tapirx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// An APIClient holds state and credentials related to uploading Asset
// information to a REST API endpoint.
type APIClient struct {
	url       string
	authToken string
	clientID  string
	enabled   bool
	semaphore chan bool
}

// NewAPIClient creates a new APIClient.
func NewAPIClient(
	apiURL string,
	apiToken string,
	clientID string,
	apiLimit int,
	enabled bool,
) *APIClient {
	apiClient := new(APIClient)
	apiClient.url = apiURL
	apiClient.authToken = apiToken
	apiClient.clientID = clientID
	apiClient.enabled = enabled

	// A channel will act as a semaphore with the desired level of concurrency
	// Full example here: http://jmoiron.net/blog/limiting-concurrency-in-go/
	apiClient.semaphore = make(chan bool, apiLimit)

	return apiClient
}

func marshal(as *AssetSet) ([]byte, error) {
	var assets []Asset
	for _, asset := range as.Assets {
		assets = append(assets, *asset)
	}
	return json.Marshal(assets)
}

// Emit sends information about a single asset to a REST API.
func (apiClient *APIClient) Emit(a *Asset) error {
	as := NewAssetSet()
	as.Add(a)
	return apiClient.EmitSet(as)
}

// EmitSet sends information for all Assets in an AssetSet to a REST API.
//
// Returns response data, if any, and error, either of which may be nil.
func (apiClient *APIClient) EmitSet(as *AssetSet) error {
	// Handle API throttling.  If the number of outstanding requests exceeds the
	// limit, return an error.
	if len(apiClient.semaphore) == cap(apiClient.semaphore) {
		log.Printf("Ignoring API request due to throttling")
		return fmt.Errorf("Ignoring API request due to throttling")
	}
	apiClient.semaphore <- true
	defer func() { <-apiClient.semaphore }()

	// Build JSON output: a list of marshaled Assets
	marshaled, err := marshal(as)
	if err != nil {
		return fmt.Errorf("Error marshalling JSON: %s", err)
	}

	// Build request object
	httpClient := http.Client{
		Timeout: time.Duration(5 * time.Second),
	}
	request, err := http.NewRequest(
		http.MethodPost,
		apiClient.url,
		bytes.NewBuffer(marshaled),
	)
	if err != nil {
		return fmt.Errorf("Error building request object: %s", err)
	}
	request.Header.Set("Content-Type", "application/json")

	if apiClient.authToken != "" {
		tokHdr := fmt.Sprintf("Token %s", apiClient.authToken)
		request.Header.Set("Authorization", tokHdr)
	}

	// Send request
	response, err := httpClient.Do(request)
	if err != nil {
		// An error is returned if caused by client policy (such as CheckRedirect),
		// or failure to speak HTTP (such as a network connectivity problem). A
		// non-2xx status code doesn't cause an error.
		return fmt.Errorf("Error making request: %s", err)
	}

	// Check status code of response
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Error API non-2xx response: %s", response.Status)
	}

	defer response.Body.Close()

	// Decode response JSON
	var result map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return fmt.Errorf("Error decoding response:: %s", err)
	}

	// Success
	return nil
}

// Close does nothing.
func (apiClient *APIClient) Close() error {
	return nil
}
