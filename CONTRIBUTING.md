# Contributing to Tapirx

Tapirx is an open-source tool that you can use to discover and identify medical
devices on a network. That's a broad category of devices and a big use case, so
it's a community effort!

Every contribution is valuable, but several categories of improvement are worth
highlighting:

- Support for protocols that Tapirx doesn't understand yet. In particular, some
  devices use proprietary protocols that are specific to manufacturers or
  device models.
- Support for message fields that may include extra identifiers. Some devices
  may use fields in unusual ways.
- Integrating other products with Tapirx by creating REST API endpoints.
- Tuning performance on high-throughput links.

Even if you're not writing code, you can contribute by sharing anonymized
network captures (contributors can help you anonymize them) and testing new
features.

# Building development versions

We use a `Makefile` in order to facilitate setting version information at
compile time (via `-ldflags`). Note that `make` actually runs `go install`, so
the resulting executable will actually be in `$GOPATH`.

    $ make
    $ $GOPATH/bin/tapirx -version

# Testing and code quality

We use [CircleCI](https://circleci.com/gh/virtalabs/tapirx) for automated testing.
CircleCI runs functional tests and also style and "lint" style tests to make sure
that code remains easy to read, well formatted, and thoroughly tested.

If you're developing on this codebase, here's a good workflow to maximize the
chances that your code will pass all of CircleCI's checks:

    $ go test
    $ go vet
    $ golint
    $ gofmt -w .

The `gofmt` commant might modify one or more files so that they conform.  Check
with `git status` and `git commit -m 'gofmt'` if necessary.

When writing new features, add unit tests in `*_test.go`. Open a pull request
on this project if you would like help deciding what and how to test.

# Architecture

Tapirx uses Google's capable [gopacket](https://github.com/google/gopacket)
library to listen on an interface and expose frames/packets/datagrams/payloads
to upper layers that watch for specific byte sequences.

The input to `tapirx` is a sequence of Ethernet frames, which may or may not
have VLAN tags on them.  This is what you get when you receive data from a SPAN
port.

Tapirx examines one frame at a time and does not reconstruct streams.  For each
input frame, `tapirx`'s job is to figure out whether it contains data that
includes device identifiers. The code in `*_decode.go` is relatively self
explanatory.

## Notes on specific protocols

For HL7, `tapirx` can find identifiers when an HL7 packet fits entirely inside
an MTU (i.e., within one frame). Fields that commonly contain identifiers can
be found in `hl7_decode.go` and include `PRT-*` and `OBX-18`.

For DICOM, identifiers can often be found in DICOM _Associate Request_ packets.
This type of packet includes a _Calling Application Entity Title_.  We need
only the 74 first bytes of an Associate Request to determine that it is a
well-formed packet and extract the identifier, so for this protocol we do not
need packet reassembly.

# Future goals

In order to detect identifiers from a wider range of traffic types, it would be
good to implement packet reassembly so we can parse payloads that span multiple
frames/packets.  [Notes on gopacket TCP
reassembly](https://godoc.org/github.com/google/gopacket/tcpassembly) will come
in handy.
