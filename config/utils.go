package config

import (
	"net"
)

// src: https://gist.github.com/player0k/038afe3031ee8d0176839a7542c086a5
func InferDefaultNInterface() *string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, iface := range ifaces {
		if (iface.Flags&net.FlagUp) != 0 && (iface.Flags&net.FlagLoopback) == 0 {
			addrs, err := iface.Addrs()
			if err != nil {
				return nil
			}
			for _, addr := range addrs {
				ipnet, ok := addr.(*net.IPNet)
				if ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
					return &iface.Name
				}
			}
		}
	}
	return nil
}
