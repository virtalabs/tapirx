// Copyright 2019 Virta Laboratories, Inc.  All rights reserved.

package tapirx

import (
	"log"
)

// AssetEmitter emits Asset information to some kind of output.
type AssetEmitter interface {
	Emit(a *Asset) error
	EmitSet(a *AssetSet) error
	Close() error
}

// LoggingEmitter is an AssetEmitter that outputs to a log.
type LoggingEmitter struct{}

// Emit prints a n Asset to a log.
func (le LoggingEmitter) Emit(a *Asset) error {
	log.Println(a.String())
	return nil
}

// EmitSet emits an AssetSet in arbitrary order.
func (le LoggingEmitter) EmitSet(as *AssetSet) error {
	as.Lock()
	defer as.Unlock()
	for _, asset := range as.Assets {
		if err := le.Emit(asset); err != nil {
			return err
		}
	}
	return nil
}

// Close does nothing.
func (le LoggingEmitter) Close() error {
	return nil
}
