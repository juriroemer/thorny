package main

type Config struct {
	Network struct {
		Iface       string `yaml:"interface"`
		Promiscuous bool   `yaml:"promiscuous"`
	}

	Logging struct {
		Snaplen           int `yaml:"snaplen"`
		Packetsperlogfile int `yaml:"packetsperlogfile"`
	}

	Filters []Filter
}

type Filter struct {
	Name   string `yaml:"name"`
	Config any    `yaml:"config"`
}
