package config

import (
	"log/slog"
	"net"
	"os"

	"github.com/juriroemer/thorny/filter"
	"github.com/juriroemer/thorny/handler"
	"go.yaml.in/yaml/v4"
)

// Configuration struct, holds config file configuration
type Config struct {
	C2 net.IP `yaml:"c2"`

	Network struct {
		Ips         []net.IP
		PrimaryIP   net.IP
		Iface       string `yaml:"iface"`
		Promiscuous bool   `yaml:"promiscuous"`
	}

	Logging struct {
		Snaplen           int    `yaml:"snaplen"`
		Packetsperlogfile int    `yaml:"packetsperlogfile"`
		LogDir            string `yaml:"logDir"`
	}

	Snort struct {
		Rules string `yaml:"rules"`
	}

	Filters []filter.CfgFilter `yaml:"filters"`

	Handlers handler.Handlers `yaml:"handlers"`

	Tls map[any]any `yaml:"tls"`
}

// NewConfig constructs a new config struct, infers network interface and IP
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

	iface := InferDefaultNInterface()
	if iface != nil {
		addrs, err := iface.Addrs()
		if err != nil {
			slog.Warn("failed to get addresses for interface", "iface", iface.Name, "err", err)
		} else {
			ips := ExtractIPs(addrs)
			filtered := FilterSensorIPs(ips)
			config.Network.Ips = filtered
			config.Network.PrimaryIP = ChoosePrimaryIP(filtered)
		}
	} else {
		slog.Warn("no default network interface inferred; Network.Ips will be empty")
	}

	// config defaults; the new yaml fork yaml/go-yaml does not seem to have default values yet :(
	if config.Network.Iface == "" && iface != nil {
		config.Network.Iface = iface.Name
	}

	return config, nil
}
