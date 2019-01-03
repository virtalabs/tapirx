GOFILES = $(wildcard *.go)
GOPATH  = $(shell go env GOPATH)
GITREV ?= $(shell git describe --always --dirty)
LDFLAGS = -ldflags "-X main.Version=$(GITREV)"
EXENAME = tapirx

.PHONY: all deps clean install test

all: install

deps:
	go get

install: ${GOPATH}/bin/$(EXENAME)

test:
	go test

${GOPATH}/bin/$(EXENAME): $(GOFILES)
	go install $(LDFLAGS)

clean:
	go clean
