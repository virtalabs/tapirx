GOFILES = $(wildcard *.go)
GOPATH  = $(shell go env GOPATH)
GITREV ?= $(shell git describe --always --dirty)
LDFLAGS = -ldflags "-X tapirx.Version=$(GITREV)"
EXENAME = tapirx
export GO111MODULE = on

.PHONY: all deps clean install test

all: install

deps:
	go mod tidy

install: ${GOPATH}/bin/$(EXENAME)

test:
	go test -v ./...

${GOPATH}/bin/$(EXENAME): $(GOFILES)
	go install $(LDFLAGS) ./...

clean:
	go clean
