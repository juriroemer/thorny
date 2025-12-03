package config

import (
	"log/slog"
	"net"
	"os"

	"github.com/juriroemer/thorny/filter"
	"github.com/juriroemer/thorny/handler"
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

	Snort struct {
		Rules string `yaml:"rules"`
	}

	Filters []filter.CfgFilter `yaml:"filters"`

	Handlers handler.Handlers `yaml:"handlers"`
}

func (c *Config) validate() bool {
	slog.Warn("Config validation not implemented.")
	return true
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

	// config defaults; the new yaml fork yaml/go-yaml does not seem to have default values yet :(
	if config.Network.Iface == "" {
		config.Network.Iface = *InferDefaultNInterface()
	}

	config.validate()

	return config, nil
}
