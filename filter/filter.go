package filter

import (
	"github.com/google/gopacket"
)

type FilterConfig interface{}
type FilterPlugin interface {
	Name() string
	New(config FilterConfig) (FilterInstance, error)
}

type CfgFilter struct {
	Name   string       `yaml:"name"`
	Config FilterConfig `yaml:"config"`
}

type FilterInstance interface {
	Match(gopacket.Packet) bool
}

type FilterRegistry struct {
	filterPlugins map[string]FilterPlugin
	active        map[string]FilterInstance
}

func NewFilterRegistry() *FilterRegistry {
	return &FilterRegistry{
		filterPlugins: make(map[string]FilterPlugin),
		active:        make(map[string]FilterInstance),
	}
}

func (f *FilterRegistry) Init() error {
	f.Register(IpFilterPlugin{})
	return nil
}

func (f *FilterRegistry) Register(p FilterPlugin) {
	f.filterPlugins[p.Name()] = p
}

func (f *FilterRegistry) Deregister(name string) {
	delete(f.filterPlugins, name)
}

func (r *FilterRegistry) Activate(f CfgFilter) error {
	plugin := r.filterPlugins[f.Name]
	instance, err := plugin.New(f.Config)
	if err != nil {
		return err
	}
	r.active[f.Name] = instance
	return nil
}

func (f *FilterRegistry) Deactivate(filterName string) {
	delete(f.active, filterName)
}

func (f *FilterRegistry) Validate(p gopacket.Packet) bool {
	for _, af := range f.active {
		if !af.Match(p) {
			return false
		}
	}
	return true
}
