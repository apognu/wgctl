package wireguard

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func getKey() []byte {
	k, _ := base64.StdEncoding.DecodeString(GeneratePrivateKey())
	return k
}

func getPSK() []byte {
	k, _ := hex.DecodeString(GeneratePSK())
	return k
}

func getEndpoint() *UDPAddr {
	ip := []byte{byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255))}
	port := rand.Intn(65000)
	return &UDPAddr{IP: net.IP(ip), Port: port}
}

func Test_SetDevice(t *testing.T) {
	instance := "wgtest"
	c := &Config{
		Interface: Interface{
			ListenPort: 12345,
			FWMark:     54321,
			PrivateKey: getKey(),
		},
		Peers: []*Peer{
			{
				PublicKey: getKey(),
				Endpoint:  getEndpoint(),
			},
			{
				PublicKey:    getKey(),
				PresharedKey: getPSK(),
			},
			{
				PublicKey:    getKey(),
				Endpoint:     getEndpoint(),
				PresharedKey: getPSK(),
			},
		},
	}

	AddDevice(instance, c)
	err := ConfigureDevice(instance, c)
	assert.Nil(t, err)

	dev, _, err := GetDevice(instance)

	assert.Nil(t, err)
	assert.Equal(t, instance, dev.Name)
	assert.Equal(t, c.Interface.ListenPort, dev.ListenPort)
	assert.Equal(t, c.Interface.FWMark, dev.FirewallMark)
	assert.Equal(t, c.Interface.PrivateKey.String(), dev.PrivateKey.String())

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
		if p.PresharedKey == EmptyPSK {
			assert.Nil(t, cp.PresharedKey)
		} else {
			assert.Equal(t, cp.PresharedKey.String(), fmt.Sprintf("%x", p.PresharedKey[:]))
		}
	}

	DeleteDevice(instance)
}
