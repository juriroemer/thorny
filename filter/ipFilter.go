package filter

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var name = "ipfilter"

type IpFilterConfig struct {
	Ips []string `yaml:"ips"`
}

func NewIpFilter(config FilterConfig) FilterRecord {
	b, _ := json.Marshal(config)
	var m IpFilterConfig
	json.Unmarshal(b, &m)

	return FilterRecord{
		Name:     name,
		Config:   m,
		Function: IpFilter,
	}
}

// make this a struct function, s.t. e.g. (*f FilterRecord) can use f.config directly -> no need for type assertion
func IpFilter(p gopacket.Packet, config FilterConfig) bool {
	layer := p.Layer(layers.LayerTypeIPv4)

	ipv4, ok := layer.(*layers.IPv4)
	if !ok {
		return true
	}

	// TODO move parsing of IP/IPNET into filter config parsing
	for _, ipS := range config.(IpFilterConfig).Ips {

		ipAdd := net.ParseIP(ipS)
		fmt.Println(ipv4.DstIP, ipv4.SrcIP)
		if ipAdd != nil {
			if ipv4.DstIP.Equal(ipAdd) {
				return false
			}
		} else {
			if _, ipNet, err := net.ParseCIDR(ipS); err == nil {
				if ipNet.Contains(ipv4.DstIP) {
					return false
				}
			}
		}
	}
	return true
}
