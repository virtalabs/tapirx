// Copyright 2019 Virta Laboratories, Inc.  All rights reserved.
/*
Signal handling.
*/

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// registerInterruptHandler spawns a goroutine that listens for an interrupt
// signal (e.g., Ctrl-C) and prints the global Stats object to standard output.
func registerInterruptHandler() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig // eat the signal
		fmt.Println(stats.String())
		os.Exit(0)
	}()
}
