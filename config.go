package main

import (
	"fmt"

	"github.com/apognu/wgctl/lib"
	"github.com/apognu/wgctl/wireguard"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v2"

	nl "github.com/vishvananda/netlink"
)

func exportConfig(instance string) {
	currentConfig, _ := lib.ParseConfig(instance)

	wgdev, rtdev, err := wireguard.GetDevice(instance)
	if err != nil {
		logrus.Fatal(err)
	}

	c := lib.Config{
		Self: &lib.Peer{},
	}

	addrs4, err4 := nl.AddrList(rtdev, unix.AF_INET)
	addrs6, err6 := nl.AddrList(rtdev, unix.AF_INET6)
	if !lib.AnyError(err4, err6) && len(addrs4)+len(addrs6) > 0 {
		addrs := append(addrs4, addrs6...)
		ip := addrs[0].IP
		mask, _ := addrs[0].IPNet.Mask.Size()

		c.Self.Address = &lib.IPMask{IP: ip, Mask: mask}
	}

	priv := lib.PrivateKey{Path: "/path/to/private.key"}
	description := ""
	preDown := [][]string{}
	postUp := [][]string{}
	routes := new(bool)
	if currentConfig != nil {
		priv = currentConfig.PrivateKey
		description = currentConfig.Description
		preDown = currentConfig.Self.PreDown
		postUp = currentConfig.Self.PostUp
		routes = currentConfig.Self.SetUpRoutes
	}

	c.Description = description
	c.PrivateKey = priv
	c.Self.ListenPort = wgdev.ListenPort
	c.Self.FWMark = wgdev.FirewallMark
	c.Self.PreDown = preDown
	c.Self.PostUp = postUp
	c.Self.SetUpRoutes = routes

	peers := make([]*lib.Peer, len(wgdev.Peers))
	for idx, wgp := range wgdev.Peers {
		description := ""
		if currentConfig != nil {
			if cp := currentConfig.GetPeer(wgp.PublicKey.String()); cp != nil {
				description = cp.Description
			}
		}

		p := &lib.Peer{
			Description:       description,
			PublicKey:         lib.Key(wgp.PublicKey[:]),
			KeepaliveInterval: wgp.PersistentKeepaliveInterval,
		}

		if wgp.PresharedKey != lib.EmptyPSK {
			psk := lib.PresharedKey(wgp.PresharedKey[:])
			p.PresharedKey = &psk
		}

		if wgp.Endpoint != nil {
			ep := lib.UDPAddr(*wgp.Endpoint)
			p.Endpoint = &ep
		}

		aips := make([]lib.IPNet, len(wgp.AllowedIPs))
		for idx, aip := range wgp.AllowedIPs {
			aips[idx] = lib.IPNet(aip)
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
