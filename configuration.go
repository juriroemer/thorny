package main

import (
	"net"
	"os"

	"go.yaml.in/yaml/v4"
)

type Config struct {
	C2 net.IP `yaml:"c2"`

	Network struct {
		Iface       string `yaml:"iface"`
		Promiscuous bool   `yaml:"promiscuous"`
	}

	Logging struct {
		Snaplen           int `yaml:"snaplen"`
		Packetsperlogfile int `yaml:"packetsperlogfile"`
	}

	Filters []Filter `yaml:"filters"`

	Handlers []Handlers `yaml:"handlers"`
}

func NewConfig(configPath *string) (*Config, error) {
	config := &Config{}

	file, err := os.Open(*configPath)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	decoder := yaml.NewDecoder(file)

	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

// FIXME HACK
type FilterConfig struct {
	Ips []string `yaml:"ips"`
}

type Filter struct {
	Name   string       `yaml:"name"`
	Values FilterConfig `yaml:"config"`
}

type Handlers struct {
	Port int    `yaml:"port"`
	Id   string `yaml:"id"`
}
