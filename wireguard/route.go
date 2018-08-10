package wireguard

import (
	"fmt"
	"net"
	"strings"

	sysctl "github.com/lorenzosaino/go-sysctl"
	"github.com/sirupsen/logrus"

	nl "github.com/vishvananda/netlink"
)

func SetRPFilter() {
	sysctls, _ := sysctl.GetPattern(`net\.ipv4\.conf\..*\.rp_filter`)
	for k, v := range sysctls {
		if v == "1" {
			sysctl.Set(k, "2")
		}
	}
}

func AddDevice(instance string, config *Config) {
	attrs := nl.NewLinkAttrs()
	attrs.Name = instance

	err := nl.LinkAdd(&WireGuardLink{LinkAttrs: attrs})
	if err != nil {
		logrus.Fatalf("could not create device: %s", err.Error())
	}

	l, err := nl.LinkByName(instance)
	if err != nil {
		logrus.Fatalf("could not find recently created device: %s", err.Error())
	}

	sn := net.IPNet(*config.Interface.Address)
	addr, err := nl.ParseAddr(fmt.Sprintf("%s", sn.String()))
	if err != nil {
		logrus.Fatalf("could not set device's IP address: %s", err.Error())
	}

	err = nl.AddrAdd(l, addr)
	if err != nil {
		logrus.Fatalf("could not set device's IP address: %s", err.Error())
	}

	err = nl.LinkSetUp(l)
	if err != nil {
		logrus.Fatalf("could bring up device: %s", err.Error())
	}
}

func AddDeviceRoutes(instance string, config *Config) {
	l, err := nl.LinkByName(instance)
	if err != nil {
		logrus.Fatalf("could not find recently created device: %s", err.Error())
	}

	for _, p := range config.Peers {
		for _, ip := range p.AllowedIPS {
			sub := net.IPNet(*ip)
			if strings.HasSuffix(sub.String(), "/0") {
				SetFWMark(instance, config.Interface.ListenPort)
				SetRPFilter()
				AddCatchAllRoute(l, sub, config)
			} else {
				n := net.IPNet(*ip)
				err := nl.RouteAdd(&nl.Route{Dst: &n, LinkIndex: l.Attrs().Index})
				if err != nil {
					logrus.Fatalf("could not add route: %s", err.Error())
				}
			}
		}
	}
}

func AddCatchAllRoute(l nl.Link, dst net.IPNet, config *Config) {
	r := &nl.Route{Dst: &dst, LinkIndex: l.Attrs().Index, Table: config.Interface.ListenPort}
	err := nl.RouteAdd(r)
	if err != nil {
		logrus.Fatalf("could not add route: %s", err.Error())
	}

	rule := nl.NewRule()
	rule.SuppressPrefixlen = 0
	rule.Table = 254
	rule.Priority = 32000

	err = nl.RuleAdd(rule)
	if err != nil {
		logrus.Fatalf("could not add suppress prefix length: %s", err.Error())
	}

	rule = nl.NewRule()
	rule.Mark = config.Interface.ListenPort
	rule.Invert = true
	rule.Table = config.Interface.ListenPort
	rule.Priority = 32001

	err = nl.RuleAdd(rule)
	if err != nil {
		logrus.Fatalf("could not add fwmark: %s", err.Error())
	}
}

func DeleteDevice(instance string) {
	l, err := nl.LinkByName(instance)
	if err != nil {
		logrus.Fatalf("could not delete device: %s", err.Error())
	}

	err = nl.LinkDel(l)
	if err != nil {
		logrus.Fatalf("could not delete device: %s", err.Error())
	}

	rule1 := nl.NewRule()
	rule1.Priority = 32000
	rule2 := *rule1
	rule2.Priority = 32001

	nl.RuleDel(rule1)
	nl.RuleDel(&rule2)
}
