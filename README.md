![Tapirx logo](media/tapirx-logo-github.png)

[![Build Status](https://travis-ci.org/virtalabs/tapirx.svg?branch=develop)](https://travis-ci.org/virtalabs/tapirx)
[![Go Report Card](https://goreportcard.com/badge/github.com/virtalabs/tapirx)](https://goreportcard.com/report/github.com/virtalabs/tapirx)

Tapirx ("taper ecks") passively discovers and identifies networked medical
devices.

Tapirx is written in cross-platform [Go](https://golang.org/) and runs on
Linux, macOS, and Windows. The following products already support Tapirx
discovery out of the box:

- [BlueFlow](https://virtalabs.com/blueflow/) 2.6.0 or later

# Quick Start

[Install Go](https://golang.org/doc/install), then install Tapirx:

    $ go get github.com/virtalabs/tapirx

(See [Windows instructions](#Building-on-Windows) below if you run into trouble
on Windows.)

Read a sample pcap file (included with this package) and output JSON data:

    $ tapirx -pcap testdata/HL7-ADT-UDI-PRT.pcap -verbose

List your network interfaces, then sniff live traffic and display discovered
device data:

    $ tapirx -interfaces   # show a list of interfaces available for capture
    $ tapirx -iface <interface_name> -verbose

Read on to understand how to share discovered asset information with other
tools to fit your workflow.

# Detailed Instructions

## Finding Devices via a SPAN Port (a/k/a Port Mirroring)

In this configuration, a single network switchport will receive a copy of all
traffic arriving at a set of switchports you want to monitor. A typical
"managed" switch can copy traffic from all switchports on the switch, or just a
subset of them. Ask your network administrator to configure a [SPAN
port](https://blog.packet-foo.com/2016/11/the-network-capture-playbook-part-4-span-port-in-depth/)
(a/k/a a mirror port) on a switch or router, then connect your machine to that
port with an Ethernet cable. If you run [Wireshark](https://www.wireshark.org/)
or [`tcpdump`](https://www.tcpdump.org/) on your machine's Ethernet interface,
you should start to see traffic from the other switchports.

On the machine you've connected to the SPAN port, you should begin to see
device information as the other connected devices on the switch generate HL7 or
DICOM traffic:

    $ tapirx -iface <your_ethernet_interface> -verbose

(On Windows, you may need to run `tapirx -interfaces` to find the appropriate
interface name to pass to `-iface`, which will look like
`"\Device\NPF_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}"`.)

If you are looking for an inexpensive switch to experiment with, we suggest
[Netgear's inexpensive managed
switches](https://www.netgear.com/business/products/switches/web-managed/),
such as the GS108E, which offers eight gigabit Ethernet ports and supports port
mirroring via its web interface.

## Finding Devices via Prerecorded Pcap Files

In this configuration, you will record and analyze a pcap file, which is the
predominant format for network traffic captures.

To generate a Pcap file, run Wireshark on a machine that is connected to a SPAN
port, then save the resulting capture(s) to pcap file(s). Instead of Wireshark,
you can instead run `tcpdump -w myfile.pcap`. Or ask your network administrator
to capture traffic on your behalf and share a pcap file with you.

You can then pass the pcap file directly to Tapirx instead of specifying a
network interface:

    $ tapirx -pcap myfile.pcap

## Connecting Tapirx to Other Systems

Tapirx can share data about discovered devices with other systems. For example,
you can:

- Leave an instance running for a fixed amount of time to collect a snapshot of
  active inventory;
- Continuously catalogue devices' MAC and IP addresses along with
  identification data to maintain a high level of preparedness for security
  incidents; or
- Automatically highlight ePHI devices for HIPAA record keeping.

Device data can be automatically shared with any tool that offers a REST API.
As it discovers devices and identifiers, Tapirx will issue `POST` requests that
look like this (in this example, Tapirx spotted an infusion pump on 10.0.0.155
communicating with an EHR via HL7 on port 2575):

    $ tapirx -apiurl https://my-asset-management.example.com/assets [-apitoken MY_SECRET]

The following is POSTed to `https://my-asset-management.example.com/assets`:

```json
{
  "ipv4_address": "10.0.0.155",
  "ipv6_address": "",
  "open_port_tcp": "",
  "connect_port_tcp": "2575",
  "mac_address": "00:03:b1:b5:b6:48",
  "identifier": "Infuse-O-Matic Peach B+",
  "provenance": "HL7 PRT-10",
  "last_seen": "2019-01-02T12:37:22.938687-08:00",
  "client_id": "mymachine.example.com"
}
```

Alternatively, you can stream CSV output to a file using the `-csv`
command-line option.

Run `tapirx -help` to see more usage information.

## Building on Windows

Building Tapirx on Windows is somewhat more involved than on Linux or macOS,
but it's within reach with a tiny bit of elbow grease:

- Download and install [Go](https://golang.org/dl/)
- Download and install [TDM-GCC](http://tdm-gcc.tdragon.net/)
- Install [WinPcap](https://www.winpcap.org/install/) and the [WinPcap developer pack](https://www.winpcap.org/devel.htm)
- Start a new command prompt and `go get github.com/virtalabs/tapirx`

(This procedure will become easier once gopacket supports npcap; see
@google/gopacket#568.)

## Building on Linux

You will need to install `libpcap` development headers, which fortunately are
in most distributions' main repositories. After you have done so, the quick
start instructions should work properly.

Ubuntu (or other Debian-based distributions):

    $ sudo apt install libpcap-dev

RHEL7 or CentOS:

    $ sudo yum install libpcap-devel

# Tests and Benchmarking

Run `go test github.com/virtalabs/tapirx` to run the test suite.

Run `go test -bench=. github.com/virtalabs/tapirx` to run tests and performance
benchmarks.

# Frequently Asked Questions

## How do I select specific network traffic to monitor?

Incoming data, whether live or from a file, can be filtered using
[BPF](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter) expressions.  For
example, if we want to sniff port 2575 (common for HL7 traffic):

    $ tapirx -iface <interface_name> -bpf 'port 2575' -verbose

## What does "discover" mean?

Tapirx inspects network traffic, either live or prerecorded, and extracts
device information. Essentially, you can think of this tool as emitting a
continuous stream of clues along the lines of "this device was spotted using
the network at this moment." You can collect these clues, and over time you
will _discover_ a population of devices that use your network.

Tapirx does *not* discover devices that don't appear to be medical devices. Put
another way, if a device doesn't use HL7, DICOM, or another protocol that
Tapirx understands, it won't appear in Tapirx's announcements. This is by
design, as medical devices merit special attention and there are plenty of
other tools that can simply regurgitate MAC-to-IP mappings. (For example, if
you run `tcpdump arp` for long enough, you'll get a sense of a network
segment's population over time but you won't see information extracted from
medical device protocols.)

To risk stating the obvious, Tapirx won't discover devices that never use the
network.

## What does "identify" mean?

Tapirx can help you answer the following questions about many devices:

- Is this a medical device?
- Does this device connect to an EHR or DICOM system?
- What is this device's manufacturer and model?
- What is this device's [GUDID](https://www.fda.gov/medicaldevices/deviceregulationandguidance/uniquedeviceidentification/)?

But it may not help with the following questions, which require information
that is not generally found in network traffic:

- What software is this device running?
- What is this device's serial number?

## What protocols can Tapirx currently inspect?

HL7 and DICOM. Support for more discovery methods and protocol fields is on the
way. See the _Contributing_ section to see how you can help.

## What can't Tapirx do?

Tapirx can extract device identifiers from medical devices' network traffic,
but it will not attempt to guess a device's identity if it cannot find relevant
information.

One simple way to assign (somewhat reliable) manufacturer information to
discovered devices is to connect Tapirx to a system that looks up MAC addresses
in the [public OUI database](https://www.wireshark.org/tools/oui-lookup.html).
Plenty of free and commercial tools fit the bill.

There are many, many medical devices out there. Contact the maintainers if you
would like to see support for a specific kind of medical device that Tapirx
does not adequately discover or identify.

## Are there prebuilt releases so I don't have to build Tapirx myself?

Not yet, but building it yourself requires only one `go get` command; see
above.

## Why is Tapirx free?
Three reasons:

- Discovery and identification of networked devices are crucial building blocks
  for cybersecurity, but they're not the most interesting parts. Democratizing
  this important function means organizations can move past initial stumbling
  blocks.
- You deserve complete control over your data (such as ePHI). You shouldn't
  have to give a company or a proprietary data collector all of your
  proprietary traffic in order to catalogue your own devices.
- Free tools scale better. Given the variety of devices in the world and the
  prohibitive cost of scaling proprietary tools in modern healthcare
  environments, the community needs free, open-source tools that aren't locked
  into a single vendor's product line.

# Contributing

This is a community project, and contributions from the community are welcome!
We have written [a guide for contributing](CONTRIBUTING.md).

# Authors

The original authors of this project are Andrew DeOrio (@awdeorio), Henrik Holm
(@ukrutt), and Ben Ransford (@ransford) of [Virta
Labs](https://virtalabs.com/).

This project would be far more complex if it weren't for the following
open-source software:

- [google/gopacket](https://github.com/google/gopacket/)
- [deoxxa/hl7](https://github.com/deoxxa/hl7)
- [grailbio/go-netdicom](https://github.com/grailbio/go-netdicom/)
