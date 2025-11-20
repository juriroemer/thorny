package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const (
	interfaceName   = "en0"
	snaplen         = 1500
	logSizeInPakets = 1000
)

var filters = []func() bool{}

func RegisterFilter(f func() bool) error {
	filters = append(filters, f)
	return nil
}

func main() {
	slog.Info("Running our applicaiton...")

	// Get handler attached to an interface.
	handle, err := pcap.OpenLive(interfaceName, snaplen, true, pcap.BlockForever)
	if err != nil {
		slog.Error("Could not OpenLive", slog.String("err", err.Error()))
		os.Exit(1)
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		slog.Error("Could not OpenLive", slog.String("err", err.Error()))
		os.Exit(1)
	}

	// Start new Source reader.
	source := gopacket.NewPacketSource(handle, handle.LinkType())

	// Reading packages.
	var count = 1
	os.Mkdir("logs", 0777)
	var filename = fmt.Sprintf("logs/log-%s.pcap", time.Now().Format("2006-01-02_15:04:05"))

	// This is suppose to be a file writer, but we will use memory, just for simplification.
	fileWriter, _ := os.Create(filename)
	pcapWriter := pcapgo.NewWriterNanos(fileWriter)
	err = pcapWriter.WriteFileHeader(snaplen, handle.LinkType())
	if err != nil {
		slog.Error("Could not write pcap header", slog.String("err", err.Error()))
		os.Exit(1)
	}

	for packet := range source.Packets() {
		if count%logSizeInPakets == 0 {
			filename = fmt.Sprintf("logs/log-%s.pcap", time.Now().Format("2006-01-02_15:04:05"))
			fileWriter, _ = os.Create(filename)
			pcapWriter = pcapgo.NewWriterNanos(fileWriter)
			err = pcapWriter.WriteFileHeader(snaplen, handle.LinkType())
			if err != nil {
				slog.Error("Could not write pcap header", slog.String("err", err.Error()))
				os.Exit(1)
			}
			count = 1
		}

		// Filter by outcoming traffic only.
		// To filter it, we need to compare MAC addresses from out interface and source MAC.
		// To access a mac Address we need to get an Ethernet layer.
		layer := packet.Layer(layers.LayerTypeEthernet)

		ethernet, ok := layer.(*layers.Ethernet)
		if !ok {
			slog.Error("Could not get Ethernet layer")
			continue
		}

		if !bytes.Equal(ethernet.SrcMAC, iface.HardwareAddr) {
			// Our interface did not send this packet. It's not outcoming.

		}

		// Now we need to identify IPv4 layer.
		layer = packet.Layer(layers.LayerTypeIPv4)

		ipv4, ok := layer.(*layers.IPv4)
		if !ok {
			// It's not IPv4 traffic.
			continue
		}

		if ipv4.DstIP.IsPrivate() {
			// Do not collect private traffic.
			continue
		}

		if ipv4.Protocol != layers.IPProtocolUDP {
			// Ignore not UDP protocol.

		}

		err = pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if err != nil {
			slog.Error("Could not write a packet to a pcap writer", slog.String("err", err.Error()))

			continue
		}

		slog.Info("Stored packet", slog.Any("packet", packet))

		// Let's collect ONLY 100K bytes, just for example perposes.
		/* 		if fileWriter.Len() > 100000 {
			break
		} */

		count = count + 1
	}

	slog.Info("We have successfuly collected bytes")
}
