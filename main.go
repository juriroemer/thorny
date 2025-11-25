package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/juriroemer/thorny/config"
	"github.com/juriroemer/thorny/filter"
)

const (
	interfaceName = "en0" // Ubuntu: "eth0", Macos: "en0"
	snaplen       = 1500
	//logSizeInPakets = 1000
)

var filters = []func() bool{}

func RegisterFilter(f func() bool) error {
	filters = append(filters, f)
	return nil
}

func main() {
	configFile := flag.String("config", "config.yaml", "the path of the config file")
	flag.Parse()

	config, err := config.NewConfig(configFile)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(config)

	// Get handler attached to an interface.
	handle, err := pcap.OpenLive(interfaceName, snaplen, config.Network.Promiscuous, pcap.BlockForever)
	if err != nil {
		slog.Error("Could not OpenLive", slog.String("err", err.Error()))
		os.Exit(1)
	}

	/* iface, err := net.InterfaceByName(interfaceName) */
	if err != nil {
		slog.Error("Could not OpenLive", slog.String("err", err.Error()))
		os.Exit(1)
	}

	fr := filter.NewFilterRegistry()
	fr.Init()

	for _, f := range config.Filters {
		fr.Activate(f)
	}

	// Start new Source reader.
	source := gopacket.NewPacketSource(handle, handle.LinkType())

	/* 	// Reading packages.
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
	   	} */

	for packet := range source.Packets() {
		layer := packet.Layer(layers.LayerTypeIPv4)
		_, ok := layer.(*layers.IPv4)
		if !ok {
			// It's not IPv4 traffic.
			continue
		}

		if fr.Validate(packet) {
			fmt.Println("VALID")
		} else {
			fmt.Println("NOT VALID")
		}
		/* if count%logSizeInPakets == 0 {
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

		if ipv4.Protocol != layers.IPProtocolTCP {
			// Ignore not TCP protocol.
			continue
		}

		if ipv4.SrcIP.Equal(net.IPv4(139, 59, 129, 123)) || ipv4.DstIP.Equal(net.IPv4(139, 59, 129, 123)) {
			// Ignore specific DO IP
			continue
		}

		err = pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if err != nil {
			slog.Error("Could not write a packet to a pcap writer", slog.String("err", err.Error()))

			continue
		}

		slog.Info("Stored packet", slog.Any("packet", packet))

		// Let's collect ONLY 100K bytes, just for example perposes.
		 		if fileWriter.Len() > 100000 {
			break
		}

		count = count + 1 */
	}

}
