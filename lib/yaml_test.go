package lib

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_UnmarshalIPMask(t *testing.T) {
	ip := new(IPMask)
	err := ip.UnmarshalYAML(func(i interface{}) error {
		*i.(*string) = "not_an_ip"
		return nil
	})

	assert.NotNil(t, err)

	err = ip.UnmarshalYAML(func(i interface{}) error {
		*i.(*string) = "127.0.0.1/8"
		return nil
	})

	assert.Nil(t, err)
	assert.NotNil(t, ip.IP.To4())
	assert.Equal(t, []byte{127, 0, 0, 1}, []byte(ip.IP[len(ip.IP)-4:]))
	assert.Equal(t, 8, ip.Mask)
}

func Test_UnmarshalIPMask6(t *testing.T) {
	ip := new(IPMask)
	err := ip.UnmarshalYAML(func(i interface{}) error {
		*i.(*string) = "fe80:cafe:b00b:1:2::1/64"
		return nil
	})

	assert.Nil(t, err)
	assert.Nil(t, ip.IP.To4())
	assert.Equal(t, []byte{254, 128, 202, 254, 176, 11, 0, 1, 0, 2, 0, 0, 0, 0, 0, 1}, []byte(ip.IP))
	assert.Equal(t, 64, ip.Mask)
}

func Test_MarshalIPMask(t *testing.T) {
	ip := IPMask{IP: net.ParseIP("192.168.255.254"), Mask: 24}
	out, err := ip.MarshalYAML()

	assert.Nil(t, err)
	assert.Equal(t, "192.168.255.254/24", out)
}

func Test_MarshalIPMask6(t *testing.T) {
	ip := IPMask{IP: net.ParseIP("fe80:cafe:b00b:1:2::10"), Mask: 48}
	out, err := ip.MarshalYAML()

	assert.Nil(t, err)
	assert.Equal(t, "fe80:cafe:b00b:1:2::10/48", out)
}

func Test_UnmarshalIPNet(t *testing.T) {
	ip := new(IPNet)
	err := ip.UnmarshalYAML(func(i interface{}) error {
		*i.(*string) = "not_an_ip"
		return nil
	})

	assert.NotNil(t, err)

	err = ip.UnmarshalYAML(func(i interface{}) error {
		*i.(*string) = "127.0.0.1/8"
		return nil
	})

	assert.Nil(t, err)
	assert.NotNil(t, ip.IP.To4())
	assert.Equal(t, []byte{127, 0, 0, 0}, []byte(ip.IP[len(ip.IP)-4:]))
}

func Test_UnmarshalIPNet6(t *testing.T) {
	ip := new(IPNet)
	err := ip.UnmarshalYAML(func(i interface{}) error {
		*i.(*string) = "fe80:cafe:b00b:1234:4321::32/48"
		return nil
	})

	assert.Nil(t, err)
	assert.Nil(t, ip.IP.To4())
	assert.Equal(t, []byte{254, 128, 202, 254, 176, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, []byte(ip.IP))
}

func Test_MarshalIPNet(t *testing.T) {
	_, sub, _ := net.ParseCIDR("192.168.255.254/24")
	out, err := IPNet(*sub).MarshalYAML()

	assert.Nil(t, err)
	assert.Equal(t, "192.168.255.0/24", out)
}

func Test_MarshalIPNet6(t *testing.T) {
	_, sub, _ := net.ParseCIDR("fe80:b00b:cafe:4321::1002/48")
	out, err := IPNet(*sub).MarshalYAML()

	assert.Nil(t, err)
	assert.Equal(t, "fe80:b00b:cafe::/48", out)
}

func Test_UnmarshalUDPAddr(t *testing.T) {
	addr := new(UDPAddr)
	err := addr.UnmarshalYAML(func(i interface{}) error {
		*i.(*string) = "not_an_ip"
		return nil
	})

	assert.NotNil(t, err)

	err = addr.UnmarshalYAML(func(i interface{}) error {
		*i.(*string) = "127.0.0.1:12345"
		return nil
	})

	assert.Nil(t, err)
	assert.NotNil(t, addr.IP.To4())
	assert.Equal(t, "127.0.0.1", addr.IP.String())
	assert.Equal(t, 12345, addr.Port)
}

func Test_UnmarshalUDPAddr6(t *testing.T) {
	addr := new(UDPAddr)
	err := addr.UnmarshalYAML(func(i interface{}) error {
		*i.(*string) = "[2001:1234:cafe::1:1]:12345"
		return nil
	})

	assert.Nil(t, err)
	assert.Nil(t, addr.IP.To4())
	assert.Equal(t, []byte{32, 1, 18, 52, 202, 254, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1}, []byte(addr.IP))
	assert.Equal(t, 12345, addr.Port)
}

func Test_MarshalUDPAddr(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "192.168.255.254:12345")
	out, err := UDPAddr(*addr).MarshalYAML()

	assert.Nil(t, err)
	assert.Equal(t, "192.168.255.254:12345", out)
}

func Test_MarshalUDPAddr6(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "[2001:1234:cafe::1:1]:12345")
	out, err := UDPAddr(*addr).MarshalYAML()

	assert.Nil(t, err)
	assert.Equal(t, "[2001:1234:cafe::1:1]:12345", out)
}

func Test_UnmarshalPrivateKey(t *testing.T) {
	createPKey(t)
	key := new(PrivateKey)
	err := key.UnmarshalYAML(func(i interface{}) error {
		*i.(*string) = "/etc/hosts"
		return nil
	})

	assert.NotNil(t, err)

	err = key.UnmarshalYAML(func(i interface{}) error {
		*i.(*string) = "/not/a/file"
		return nil
	})

	assert.NotNil(t, err)

	err = key.UnmarshalYAML(func(i interface{}) error {
		*i.(*string) = "/tmp/testing.key"
		return nil
	})

	assert.Nil(t, err)
	assert.Equal(t, "7X78dxEtCqCzVTxFYnxCcjxviI1vzeTl13yq+7rdPD4=", key.String())
}

func Test_MarshalPrivateKey(t *testing.T) {
	key := PrivateKey{Path: "/path/to/private.key"}
	out, err := key.MarshalYAML()

	assert.Nil(t, err)
	assert.Equal(t, out, "/path/to/private.key")
}

func Test_UnmarshalKey(t *testing.T) {
	key := new(Key)
	err := key.UnmarshalYAML(func(i interface{}) error {
		return fmt.Errorf("wrong data type")
	})

	assert.NotNil(t, err)

	err = key.UnmarshalYAML(func(i interface{}) error {
		*i.(*string) = "not_a_key"
		return nil
	})

	assert.NotNil(t, err)

	err = key.UnmarshalYAML(func(i interface{}) error {
		*i.(*string) = "uJtUEgdOFdszfiVbMVGdd7/la9k7P9+iUHRzJFtVfWc="
		return nil
	})

	assert.Nil(t, err)
	assert.Equal(t, "uJtUEgdOFdszfiVbMVGdd7/la9k7P9+iUHRzJFtVfWc=", key.String())
}

func Test_MarshalKey(t *testing.T) {
	key := Key(GetKey(t))
	out, err := key.MarshalYAML()

	assert.Nil(t, err)
	assert.Equal(t, out, key.String())
}

func Test_UnmarshalPSK(t *testing.T) {
	key := new(PresharedKey)

	err := key.UnmarshalYAML(func(i interface{}) error {
		return fmt.Errorf("wrong data type")
	})

	assert.NotNil(t, err)

	err = key.UnmarshalYAML(func(i interface{}) error {
		*i.(*string) = "not_a_key"
		return nil
	})

	assert.NotNil(t, err)

	err = key.UnmarshalYAML(func(i interface{}) error {
		*i.(*string) = "bac6b07b5d9a933a6557770bcc81bfe0017a9a690e3cd7f49d0068986ff53e92"
		return nil
	})

	assert.Nil(t, err)
	assert.Equal(t, "bac6b07b5d9a933a6557770bcc81bfe0017a9a690e3cd7f49d0068986ff53e92", key.String())
}

func Test_MarshalPSK(t *testing.T) {
	key := GetPSK(t)
	out, err := key.MarshalYAML()

	assert.Nil(t, err)
	assert.Equal(t, out, key.String())
}
