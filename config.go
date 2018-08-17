package main

import (
	"fmt"

	"github.com/apognu/wgctl/wireguard"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v2"

	nl "github.com/vishvananda/netlink"
)

func exportConfig(instance string) {
	currentConfig, _ := wireguard.ParseConfig(instance)

	wgdev, rtdev, err := wireguard.GetDevice(instance)
	if err != nil {
		logrus.Fatal(err)
	}

	c := wireguard.Config{}

	addrs, err := nl.AddrList(rtdev, unix.AF_INET)
	if err == nil && len(addrs) > 0 {
		ip := addrs[0].IP
		mask, _ := addrs[0].IPNet.Mask.Size()

		c.Interface.Address = &wireguard.IPMask{IP: ip, Mask: mask}
	}

	description := ""
	preDown := [][]string{}
	postUp := [][]string{}
	routes := new(bool)
	if currentConfig != nil {
		description = currentConfig.Interface.Description
		preDown = currentConfig.Interface.PreDown
		postUp = currentConfig.Interface.PostUp
		routes = currentConfig.Interface.SetUpRoutes
	}

	c.Interface.Description = description
	c.Interface.ListenPort = wgdev.ListenPort
	c.Interface.FWMark = wgdev.FirewallMark
	c.Interface.PreDown = preDown
	c.Interface.PostUp = postUp
	c.Interface.SetUpRoutes = routes

	peers := make([]*wireguard.Peer, len(wgdev.Peers))
	for idx, wgp := range wgdev.Peers {
		description := ""
		if currentConfig != nil {
			if cp := currentConfig.GetPeer(wgp.PublicKey.String()); cp != nil {
				description = cp.Description
			}
		}

		p := &wireguard.Peer{
			Description:       description,
			PublicKey:         wireguard.Key(wgp.PublicKey[:]),
			KeepaliveInterval: wgp.PersistentKeepaliveInterval,
		}

		if wgp.PresharedKey != wireguard.EmptyPSK {
			psk := wireguard.PresharedKey(wgp.PresharedKey[:])
			p.PresharedKey = &psk
		}

		if wgp.Endpoint != nil {
			ep := wireguard.UDPAddr(*wgp.Endpoint)
			p.Endpoint = &ep
		}

		aips := make([]wireguard.IPNet, len(wgp.AllowedIPs))
		for idx, aip := range wgp.AllowedIPs {
			aips[idx] = wireguard.IPNet(aip)
		}
		p.AllowedIPS = aips

		peers[idx] = p
	}

	c.Peers = peers

	out, err := yaml.Marshal(c)
	if err != nil {
		logrus.Fatalf("could not export configuration: %s", err.Error())
	}

	fmt.Println(string(out))
}
