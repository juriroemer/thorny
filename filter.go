package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type FilterFunction = func(gopacket.Packet, FilterConfig) bool

type FilterRecord struct {
	Name     string
	Config   FilterConfig
	Function FilterFunction
}

type FilterRegistry struct {
	filter map[string]FilterFunction // TODO make this a struct that holds FilterFunction and some kind of FilterConfigParsingFunction
	active map[string]FilterRecord
}

func IpFilter(p gopacket.Packet, config FilterConfig) bool {
	layer := p.Layer(layers.LayerTypeIPv4)

	ipv4, ok := layer.(*layers.IPv4)
	if !ok {
		return true
	}

	// TODO move parsing of IP/IPNET into filter config parsing
	for _, ipS := range config.Ips {
		ipAdd := net.ParseIP(ipS)
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

func NewFilterRegistry() *FilterRegistry {
	return &FilterRegistry{filter: make(map[string]FilterFunction), active: make(map[string]FilterRecord)}
}

func (f *FilterRegistry) Init() error {
	//fr := NewFilterRegistry()
	f.Register("ipfilter", IpFilter)
	return nil
}

func (f *FilterRegistry) Register(name string, fc FilterFunction) error {
	if _, exists := f.filter[name]; !exists {
		f.filter[name] = fc
		return nil
	} else {
		return fmt.Errorf("filter with name %s already exists", name)
	}
}

func (f *FilterRegistry) Deregister(name string) {
	delete(f.filter, name)
}

func (f *FilterRegistry) Activate(filter Filter) {
	r := &FilterRecord{Config: filter.Values, Function: f.filter[filter.Name], Name: filter.Name}
	f.active[filter.Name] = *r
}

func (f *FilterRegistry) Deactivate(filterName string) {
	delete(f.active, filterName)
}

func (f *FilterRegistry) Validate(p gopacket.Packet) bool {
	for _, af := range f.active {
		if !f.filter[af.Name](p, af.Config) {
			return false
		}
	}
	return true
}
