package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/apognu/wgctl/lib"
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
	instances, err := filepath.Glob(fmt.Sprintf("%s/*.yml", lib.GetConfigPath()))
	if err != nil {
		logrus.Fatalf("could not enumerate your configurations: %s", err.Error())
	}

	for _, path := range instances {
		i := lib.GetInstanceFromArg(path)

		status(i, short, true)
	}
}

func info(instance string) {
	config, err := lib.ParseConfig(instance)
	if err != nil {
		logrus.Fatalf("could not parse configuration: %s", err.Error())
	}
	dev, _, err := wireguard.GetDevice(instance)
	if err != nil {
		logrus.Fatalf("could not retrieve device information: %s", err.Error())
	}

	description := "<no description provided>"
	if len(config.Description) > 0 {
		description = config.Description
	}

	PrintSection(0, "tunnel", description, tunnelColor)
	PrintAttr(1, "interface", dev.Name, true)
	PrintAttr(1, "public key", dev.PublicKey.String(), true)
	PrintAttr(1, "port", strconv.Itoa(dev.ListenPort), true)
	PrintAttr(1, "fwmark", strconv.Itoa(dev.FirewallMark), dev.FirewallMark > 0)

	if len(dev.Peers) > 0 {
		for _, p := range dev.Peers {
			description := "<no description provided>"
			if peerSpec := config.GetPeer(p.PublicKey.String()); peerSpec != nil {
				if len(peerSpec.Description) > 0 {
					description = peerSpec.Description
				}
			}

			PrintSection(1, "peer", description, peerColor)
			PrintAttr(2, "public key", p.PublicKey.String(), true)

			if p.Endpoint != nil {
				if p.Endpoint.IP.To4() != nil {
					PrintAttr(2, "endpoint", "%s:%d", true, p.Endpoint.IP, p.Endpoint.Port)
				} else {
					PrintAttr(2, "endpoint", "[%s]:%d", true, p.Endpoint.IP, p.Endpoint.Port)
				}
			}

			PrintAttr(2, "pre-shared key", FormatPSK(p.PresharedKey), p.PresharedKey != lib.EmptyPSK)

			if len(p.AllowedIPs) > 0 {
				ips := make([]string, len(p.AllowedIPs))
				for idx, ip := range p.AllowedIPs {
					ips[idx] = FormatSubnet(ip)
				}

				PrintAttr(2, "allowed ips", strings.Join(ips, ", "), true)
			}

			PrintAttr(2, "last handshake", FormatInterval(p.LastHandshakeTime), p.LastHandshakeTime.Year() > 1970)
			PrintAttr(2, "keepalive", fmt.Sprintf("every %.0f seconds", p.PersistentKeepaliveInterval.Seconds()), p.PersistentKeepaliveInterval > 0)
			PrintAttr(2, "transfer", FormatTransfer(p.ReceiveBytes, p.TransmitBytes), true)
		}
	}
}
