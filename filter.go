package main

import (
	"fmt"

	"github.com/google/gopacket"
)

type FilterFunction = func(*gopacket.Packet) bool

type FilterRegistry struct {
	filter map[string]FilterFunction
}

func (f *FilterRegistry) New() *FilterRegistry {
	return &FilterRegistry{filter: make(map[string]FilterFunction)}
}

func (f *FilterRegistry) Init(configuration *any) error {
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

func (f *FilterRegistry) Validate(p *gopacket.Packet) bool {
	for _, f := range f.filter {
		if !f(p) {
			return false
		}
	}
	return true
}
