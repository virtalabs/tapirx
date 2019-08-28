// Copyright 2019 Virta Laboratories, Inc.  All rights reserved.
/*
Signal handling.
*/

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// registerCleanupHandler spawns a goroutine that listens for a signal (e.g., Ctrl-C) and calls the
// provided cleanup function.
func registerCleanupHandler(cleanup func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig // eat the signal
		cleanup()
	}()
}
