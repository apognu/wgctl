package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/apognu/wgctl/wireguard"
	"github.com/sirupsen/logrus"
	nl "github.com/vishvananda/netlink"
)

func status(instance string, short bool, all bool) {
	if instance == "" {
		statusAll(short)
		return
	}

	l, err := nl.LinkByName(instance)
	if err != nil {
		if !short {
			Down("tunnel '%s' is down", instance)
		}
		if !all {
			os.Exit(1)
		}
		return
	}

	if l.Type() == wireguard.NetlinkName {
		if short {
			fmt.Printf("%s\n", instance)
		} else {
			Up("tunnel '%s' is up and running", instance)
		}
	} else {
		if !short {
			Down("interface '%s' does not seem to be a WireGuard device", instance)
		}
		if !all {
			os.Exit(1)
		}
	}
}

func statusAll(short bool) {
	instances, err := filepath.Glob(fmt.Sprintf("%s/*.yml", wireguard.GetConfigPath()))
	if err != nil {
		logrus.Fatalf("could not enumerate your configurations: %s", err.Error())
	}

	for _, path := range instances {
		i := wireguard.GetInstanceFromArg(path)

		status(i, short, true)
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
