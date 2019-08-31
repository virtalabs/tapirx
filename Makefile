PACKAGE  = github.com/virtalabs/tapirx
GITREV  ?= $(shell git describe --always --dirty)
LDFLAGS  = -ldflags="-X '$(PACKAGE).Version=$(GITREV)'"
COMMANDS = $(addprefix $(PACKAGE)/, $(sort $(wildcard cmd/*)))
export GO111MODULE = on

.PHONY: all build clean deps install test

all: build install

build:
	go build $(LDFLAGS) ./...

deps:
	go mod tidy

install:
	go install $(LDFLAGS) $(COMMANDS)

test:
	go test -v -race ./...

clean:
	go clean
