package wireguard

import (
	"fmt"
	"net"
	"strings"

	sysctl "github.com/lorenzosaino/go-sysctl"

	nl "github.com/vishvananda/netlink"
)

// SetRPFilter sets the rp_filter of all interaces that are set to 1, to 2
func SetRPFilter() error {
	sysctls, err := sysctl.GetPattern(`net\.ipv4\.conf\..*\.rp_filter`)
	if err != nil {
		return err
	}

	for k, v := range sysctls {
		if v == "1" {
			err := sysctl.Set(k, "2")
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// AddDevice adds a new WireGuard link and assigns the given IP address
func AddDevice(instance string, config *Config) error {
	attrs := nl.NewLinkAttrs()
	attrs.Name = instance

	err1 := nl.LinkAdd(&WGLink{LinkAttrs: attrs})
	l, err2 := nl.LinkByName(instance)
	if anyError(err1, err2) {
		return fmt.Errorf("could not find recently created device: %s", firstError(err1, err2))
	}

	if config.Interface.Address != nil {
		ip := config.Interface.Address
		addr, err := nl.ParseAddr(fmt.Sprintf("%s", ip.String()))
		if err != nil {
			return fmt.Errorf("could not set device's IP address: %s", err.Error())
		}

		err = nl.AddrAdd(l, addr)
		if err != nil {
			return fmt.Errorf("could not set device's IP address: %s", err.Error())
		}
	}

	if err := nl.LinkSetUp(l); err != nil {
		return fmt.Errorf("could bring up device: %s", err.Error())
	}

	return nil
}

// AddDeviceRoutes sets up the routes for all AllowedIPs in the peer configuration
func AddDeviceRoutes(instance string, config *Config) error {
	l, err := nl.LinkByName(instance)
	if err != nil {
		return fmt.Errorf("could not find recently created device: %s", err.Error())
	}

	for _, p := range config.Peers {
		for _, ip := range p.AllowedIPS {
			sub := net.IPNet(ip)
			if strings.HasSuffix(sub.String(), "/0") {
				err := SetFWMark(instance, config.Interface.ListenPort)
				if err != nil {
					return err
				}
				err = SetRPFilter()
				if err != nil {
					return err
				}
				err = AddCatchAllRoute(l, sub, config)
				if err != nil {
					return err
				}
			} else {
				n := net.IPNet(ip)
				err := nl.RouteAdd(&nl.Route{Dst: &n, LinkIndex: l.Attrs().Index})
				if err != nil {
					return fmt.Errorf("could not add route: %s", err.Error())
				}
			}
		}
	}

	return nil
}

// AddCatchAllRoute sets up routing to forward all traffic
func AddCatchAllRoute(l nl.Link, dst net.IPNet, config *Config) error {
	r := &nl.Route{Dst: &dst, LinkIndex: l.Attrs().Index, Table: config.Interface.ListenPort}
	err := nl.RouteAdd(r)
	if err != nil {
		return fmt.Errorf("could not add route: %s", err.Error())
	}

	rule := nl.NewRule()
	rule.SuppressPrefixlen = 0
	rule.Table = 254
	rule.Priority = 32000

	err = nl.RuleAdd(rule)
	if err != nil {
		return fmt.Errorf("could not add suppress prefix length: %s", err.Error())
	}

	rule = nl.NewRule()
	rule.Mark = config.Interface.ListenPort
	rule.Invert = true
	rule.Table = config.Interface.ListenPort
	rule.Priority = 32001

	err = nl.RuleAdd(rule)
	if err != nil {
		return fmt.Errorf("could not add fwmark: %s", err.Error())
	}

	return nil
}

// DeleteDevice deleted a WireGuard device and all routes and rules linked to it'
func DeleteDevice(instance string) error {
	l, err := nl.LinkByName(instance)
	if err != nil {
		return fmt.Errorf("could not delete device: %s", err.Error())
	}

	err = nl.LinkDel(l)
	if err != nil {
		return fmt.Errorf("could not delete device: %s", err.Error())
	}

	rule1 := nl.NewRule()
	rule1.Priority = 32000
	rule2 := *rule1
	rule2.Priority = 32001

	nl.RuleDel(rule1)
	nl.RuleDel(&rule2)

	return nil
}
