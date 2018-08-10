package main

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/apognu/wgctl/wireguard"
	"github.com/sirupsen/logrus"
	nl "github.com/vishvananda/netlink"
)

func status(instance string) {
	if instance == "" {
		statusAll()
		return
	}

	l, err := nl.LinkByName(instance)
	if err != nil {
		Down("tunnel '%s' is down", instance)
		return
	}

	if l.Type() == wireguard.NetlinkName {
		Up("tunnel '%s' is up and running", instance)
	} else {
		Down("interface '%s' does not seem to be a WireGuard device", instance)
	}
}

func statusAll() {
	instances, err := filepath.Glob("/etc/wireguard/*.yml")
	if err != nil {
		logrus.Fatalf("could not enumerate your configurations: %s", err.Error())
	}

	for _, path := range instances {
		i := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))

		status(i)
	}
}

func info(instance string) {
	dev, err := wireguard.GetDevice(instance)
	if err != nil {
		logrus.Fatalf("could not retrieve device information: %s", err)
	}

	PrintSection(0, "tunnel", "", tunnelColor)
	PrintAttr(1, "interface", dev.Name, true)
	PrintAttr(1, "public key", dev.PublicKey, true)
	PrintAttr(1, "port", strconv.Itoa(dev.ListenPort), true)
	PrintAttr(1, "fwmark", strconv.Itoa(dev.FWMark), dev.FWMark > 0)

	if len(dev.Peers) > 0 {
		for _, p := range dev.Peers {
			PrintSection(1, "peer", "", peerColor)
			PrintAttr(2, "public key", p.PublicKey, true)

			if p.Endpoint != nil {
				if p.Endpoint.IP.To4() != nil {
					PrintAttr(2, "endpoint", "%s:%d", true, p.Endpoint.IP, p.Endpoint.Port)
				} else {
					PrintAttr(2, "endpoint", "[%s]:%d", true, p.Endpoint.IP, p.Endpoint.Port)
				}
			}

			PrintAttr(2, "pre-shared key", p.PresharedKey, len(p.PresharedKey) > 0)

			if len(p.AllowedIPs) > 0 {
				ips := make([]string, len(p.AllowedIPs))
				for idx, ip := range p.AllowedIPs {
					ips[idx] = fmt.Sprintf("%s/%d", ip.Address, ip.CIDR)
				}

				PrintAttr(2, "allowed ips", strings.Join(ips, ", "), true)
			}

			PrintAttr(2, "last handshake", FormatInterval(p.LastHandshake), p.LastHandshake.Year() > 1970)
			PrintAttr(2, "keepalive", fmt.Sprintf("every %d seconds", p.KeepaliveInterval), p.KeepaliveInterval > 0)
			PrintAttr(2, "transfer", FormatTransfer(p.RXBytes, p.TXBytes), true)
		}
	}
}
