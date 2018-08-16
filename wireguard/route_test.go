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
			Address: &IPMask{IP: net.ParseIP("198.18.183.200"), Mask: 24},
		},
	}

	err := AddDevice(instance, c)
	assert.Nil(t, err)

	dev, link, err := GetDevice(instance)
	assert.Nil(t, err)
	assert.Equal(t, instance, dev.Name)

	addrs, _ := nl.AddrList(link, unix.AF_INET)
	assert.Equal(t, "198.18.183.200", addrs[0].IP.String())
	assert.Equal(t, "ffffff00", addrs[0].Mask.String())

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
