package config

import (
	"net"
)

// src: https://gist.github.com/player0k/038afe3031ee8d0176839a7542c086a5
func InferDefaultNInterface() *net.Interface {
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
					return &iface
				}
			}
		}
	}
	return nil
}

// FilterSensorIPs returns a slice of possible sensor IPs
// - excludes loopback
// - prefers IPv4, but also returns global-scope IPv6
// - excludes link-local and unspecified addresses
func FilterSensorIPs(ips []net.IP) []net.IP {
	var v4s []net.IP
	var v6s []net.IP
	for _, ip := range ips {
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			v4s = append(v4s, v4)
			continue
		}
		// IPv6: exclude link-local (fe80::/10) and multicast
		if ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			continue
		}
		v6s = append(v6s, ip)
	}
	// Return IPv4s first, then IPv6s
	return append(v4s, v6s...)
}

// ChoosePrimaryIP selects a single primary IP with preference for IPv4.
func ChoosePrimaryIP(ips []net.IP) net.IP {
	for _, ip := range ips {
		if ip != nil && ip.To4() != nil {
			return ip
		}
	}
	if len(ips) > 0 {
		return ips[0]
	}
	return nil
}

// ExtractIPs converts a list of net.Addr to IPs, skipping non-IP addresses.
func ExtractIPs(addrs []net.Addr) []net.IP {
	var res []net.IP
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			if v.IP != nil {
				res = append(res, v.IP)
			}
		case *net.IPAddr:
			if v.IP != nil {
				res = append(res, v.IP)
			}
		}
	}
	return res
}
