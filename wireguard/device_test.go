package wireguard

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/apognu/wgctl/lib"
	"github.com/stretchr/testify/assert"
)

func Test_SetDevice(t *testing.T) {
	instance := "wgtest"
	c := &lib.Config{
		PrivateKey: lib.NewPrivateKey(lib.GetKey(t)),
		Self: &lib.Peer{
			ListenPort: 12345,
			FWMark:     54321,
		},
		Peers: []*lib.Peer{
			{
				PublicKey:         lib.GetKey(t),
				Endpoint:          lib.GetEndpoint(t),
				KeepaliveInterval: 30 * time.Second,
			},
			{
				PublicKey:    lib.GetKey(t),
				PresharedKey: lib.GetPSK(t),
				AllowedIPS:   []lib.IPNet{lib.GetSubnet(t), lib.GetSubnet(t)},
			},
			{
				PublicKey:    lib.GetKey(t),
				Endpoint:     lib.GetEndpoint(t),
				PresharedKey: lib.GetPSK(t),
				AllowedIPS:   []lib.IPNet{lib.GetSubnet(t)},
			},
		},
	}

	AddDevice(instance, c)
	err := ConfigureDevice(instance, c, true)
	assert.Nil(t, err)

	dev, _, err := GetDevice(instance)

	assert.Nil(t, err)
	assert.Equal(t, instance, dev.Name)
	assert.Equal(t, c.Self.ListenPort, dev.ListenPort)
	assert.Equal(t, c.Self.FWMark, dev.FirewallMark)

	assert.Equal(t, len(c.Peers), len(dev.Peers))

	for _, p := range dev.Peers {
		cp := c.GetPeer(p.PublicKey.String())

		assert.NotNil(t, cp)
		if cp.Endpoint == nil {
			assert.Nil(t, p.Endpoint)
		} else {
			assert.Equal(t, net.UDPAddr(*cp.Endpoint), *p.Endpoint)
		}
		assert.Equal(t, len(cp.AllowedIPS), len(p.AllowedIPs))
		assert.Equal(t, cp.KeepaliveInterval, p.PersistentKeepaliveInterval)
		if p.PresharedKey == lib.EmptyPSK {
			assert.Nil(t, cp.PresharedKey)
		} else {
			assert.Equal(t, cp.PresharedKey.String(), fmt.Sprintf("%x", p.PresharedKey[:]))
		}
		assert.Equal(t, len(cp.AllowedIPS), len(p.AllowedIPs))
		for _, cip := range cp.AllowedIPS {
			match := false
			for _, ip := range p.AllowedIPs {
				if cip.IP.String() == ip.IP.String() && cip.Mask.String() == ip.Mask.String() {
					match = true
				}
			}

			assert.True(t, match)
		}
	}

	DeleteDevice(instance)
}

func Test_SetInvalidFWMark(t *testing.T) {
	err := SetFWMark("wgtest", 10)

	assert.NotNil(t, err)
}
