package filter

import (
	"fmt"
	"net"
	"slices"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.yaml.in/yaml/v4"
)

type IpFilterConfig struct {
	Ips  []net.IP
	Nets []net.IPNet
}

type IpFilterPlugin struct{}

func (IpFilterPlugin) Name() string {
	return "ipfilter"
}

func (IpFilterPlugin) New(config FilterConfig) (FilterInstance, error) {
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, err
	}
	fmt.Println(cfg)
	return &IpFilterInstance{
		cfg: *cfg,
	}, nil
}

func parseConfig(config FilterConfig) (*IpFilterConfig, error) {
	type CfgIpFilter struct {
		Ips []string `yaml:"ips"`
	}
	var ips []net.IP
	var nets []net.IPNet
	var cfg CfgIpFilter

	// Marshalling and Unmarshalling seems to be the easiest way to do this, unfortunately.
	// Anything else requires tons of manual type checking.
	// TODO: decide if this is the way to go or if i should use a custom marshaller etc
	b, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}

	for _, v := range cfg.Ips {
		if ip := net.ParseIP(v); ip != nil {
			ips = append(ips, ip)
		} else if _, ipNet, err := net.ParseCIDR(v); err == nil {
			nets = append(nets, *ipNet)
		}
	}

	return &IpFilterConfig{Ips: ips, Nets: nets}, nil
}

type IpFilterInstance struct {
	cfg IpFilterConfig
}

func (i *IpFilterInstance) Match(p gopacket.Packet) bool {
	layer := p.Layer(layers.LayerTypeIPv4)

	ipv4, ok := layer.(*layers.IPv4)
	if !ok {
		return true
	}

	fmt.Println(ipv4.DstIP, ipv4.SrcIP)

	// check filtered IPs
	if slices.ContainsFunc(i.cfg.Ips, ipv4.DstIP.Equal) {
		return false
	}

	// check filtered Nets
	for _, net := range i.cfg.Nets {
		if net.Contains(ipv4.DstIP) {
			return false
		}
	}
	return true
}
