package filter

import (
	"fmt"

	"github.com/google/gopacket"
)

type FilterConfig interface{}
type FilterFunction = func(gopacket.Packet, FilterConfig) bool
type FilterInitilizer = func(config FilterConfig) FilterRecord

type Filter struct {
	Name   string       `yaml:"name"`
	Values FilterConfig `yaml:"config"`
}

type FilterRecord struct {
	Name     string
	Config   FilterConfig
	Function FilterFunction
}

type FilterRegistry struct {
	filter map[string]FilterInitilizer // TODO make this a struct that holds FilterFunction and some kind of FilterConfigParsingFunction
	active map[string]FilterRecord
}

func NewFilterRegistry() *FilterRegistry {
	return &FilterRegistry{
		filter: make(map[string]FilterInitilizer),
		active: make(map[string]FilterRecord),
	}
}

func (f *FilterRegistry) Init() error {
	err := f.Register("ipfilter", NewIpFilter)
	return err
}

func (f *FilterRegistry) Register(name string, fi FilterInitilizer) error {
	if _, exists := f.filter[name]; !exists {
		f.filter[name] = fi
		return nil
	} else {
		return fmt.Errorf("filter with name %s already exists", name)
	}
}

func (f *FilterRegistry) Deregister(name string) {
	delete(f.filter, name)
}

func (f *FilterRegistry) Activate(filter Filter) {
	initilizer := f.filter[filter.Name]
	record := initilizer(filter.Values)
	f.active[filter.Name] = record
}

func (f *FilterRegistry) Deactivate(filterName string) {
	delete(f.active, filterName)
}

func (f *FilterRegistry) Validate(p gopacket.Packet) bool {
	for _, af := range f.active {
		if !af.Function(p, af.Config) {
			return false
		}
	}
	return true
}
