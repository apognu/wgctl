package wireguard

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	sysctl "github.com/lorenzosaino/go-sysctl"
	nl "github.com/vishvananda/netlink"
)

func Test_SetRPFilter(t *testing.T) {
	assert.Nil(t, sysctl.Set("net.ipv4.conf.lo.rp_filter", "1"))
	assert.Nil(t, SetRPFilter())

	value, err := sysctl.Get("net.ipv4.conf.lo.rp_filter")

	assert.Nil(t, err)
	assert.Equal(t, "2", value)
}

func Test_AddDevice(t *testing.T) {
	instance := "wgtest"
	c := &Config{
		Interface: Interface{
			Address: &IPMask{IP: net.ParseIP("198.18.100.1"), Mask: 24},
		},
	}

	err := AddDevice(instance, c)
	assert.Nil(t, err)

	dev, link, err := GetDevice(instance)
	assert.Nil(t, err)
	assert.Equal(t, instance, dev.Name)

	addrs, _ := nl.AddrList(link, unix.AF_INET)
	assert.Equal(t, "198.18.100.1", addrs[0].IP.String())
	assert.Equal(t, "ffffff00", addrs[0].Mask.String())

	DeleteDevice(instance)
}

func Test_AddDeviceRoutes(t *testing.T) {
	_, sub1, _ := net.ParseCIDR("198.18.201.0/24")
	_, sub2, _ := net.ParseCIDR("198.18.202.0/24")
	subn1 := IPNet(*sub1)
	subn2 := IPNet(*sub2)

	instance := "wgtest"
	c := &Config{
		Interface: Interface{
			Address: &IPMask{IP: net.ParseIP("198.18.100.1"), Mask: 24},
		},
		Peers: []*Peer{
			&Peer{AllowedIPS: []IPNet{subn1, subn2}},
		},
	}

	AddDevice(instance, c)
	err := AddDeviceRoutes(instance, c)
	assert.Nil(t, err)

	_, link, err := GetDevice(instance)

	routes, err := nl.RouteList(link, unix.AF_INET)
	assert.Nil(t, err)
	assert.Equal(t, 3, len(routes))

	DeleteDevice(instance)
}

func Test_DeleteDevice(t *testing.T) {
	instance := "wgtest"
	c := &Config{}

	AddDevice(instance, c)

	err := DeleteDevice(instance)
	assert.Nil(t, err)

	_, _, err = GetDevice(instance)
	assert.NotNil(t, err)
}