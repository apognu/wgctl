package lib

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"strings"

	"github.com/mdlayher/wireguardctrl/wgtypes"
)

// UnmarshalYAML returns an IPMask from a YAML string
func (ip *IPMask) UnmarshalYAML(f func(interface{}) error) error {
	b := new(string)
	if err := f(b); err == nil {
		if addr, cidr, err := net.ParseCIDR(*b); err == nil {
			mask, _ := cidr.Mask.Size()
			*ip = IPMask{
				IP:   addr,
				Mask: mask,
			}
			return nil
		}
	}

	return fmt.Errorf("could not parse IP address: %s", *b)
}

// MarshalYAML returns the YAML string representation of an IPMask
func (ip *IPMask) MarshalYAML() (interface{}, error) {
	return fmt.Sprintf("%s/%d", ip.IP.String(), ip.Mask), nil
}

// UnmarshalYAML returns an IPNet from a YAML string
func (ip *IPNet) UnmarshalYAML(f func(interface{}) error) error {
	b := new(string)
	if err := f(b); err == nil {
		if _, cidr, err := net.ParseCIDR(*b); err == nil {
			*ip = IPNet(*cidr)
			return nil
		}
	}

	return fmt.Errorf("could not parse IP address: %s", *b)
}

// MarshalYAML returns the YAML string representation of an IPNet
func (ip IPNet) MarshalYAML() (interface{}, error) {
	cidr, _ := ip.Mask.Size()
	return fmt.Sprintf("%s/%d", ip.IP, cidr), nil
}

// UnmarshalYAML returns an UDPAddr from a YAML string
func (ip *UDPAddr) UnmarshalYAML(f func(interface{}) error) error {
	b := new(string)
	if err := f(b); err == nil {
		if addr, err := net.ResolveUDPAddr("udp", *b); err == nil {
			*ip = UDPAddr(*addr)
			return nil
		}
	}

	return fmt.Errorf("could not parse UDP address: %s", *b)
}

// MarshalYAML returns the YAML string representation of an UDPAddr
func (ip UDPAddr) MarshalYAML() (interface{}, error) {
	if ip.IP.To4() != nil {
		return fmt.Sprintf("%s:%d", ip.IP.String(), ip.Port), nil
	}
	return fmt.Sprintf("[%s]:%d", ip.IP.String(), ip.Port), nil
}

// UnmarshalYAML returns an private key from a YAML file path
func (k *PrivateKey) UnmarshalYAML(f func(interface{}) error) error {
	b := new(string)
	if err := f(b); err == nil {
		if key, err := ioutil.ReadFile(*b); err == nil {
			b64key := strings.TrimSpace(string(key))
			key, err = base64.StdEncoding.DecodeString(b64key)
			if err != nil || len(key) != wgtypes.KeyLen {
				return fmt.Errorf("key is of invalid size")
			}

			bk := new([wgtypes.KeyLen]byte)
			copy(bk[:], key)

			*k = PrivateKey{
				Path: *b,
				Data: *bk,
			}
			return nil
		}
	}

	return fmt.Errorf("could not open private key file")
}

// MarshalYAML returns the YAML string representation of a PrivateKeyFile
func (k PrivateKey) MarshalYAML() (interface{}, error) {
	return k.Path, nil
}

// UnmarshalYAML returns a Key from a YAML string
func (k *Key) UnmarshalYAML(f func(interface{}) error) error {
	b := new(string)
	if err := f(b); err == nil {
		b64key := strings.TrimSpace(*b)
		key, err := base64.StdEncoding.DecodeString(b64key)
		if err != nil || len(key) != wgtypes.KeyLen {
			return fmt.Errorf("key is of invalid size")
		}

		*k = key
		return nil
	}

	return fmt.Errorf("could not parse public key")
}

// MarshalYAML returns the YAML string representation of a Key
func (k Key) MarshalYAML() (interface{}, error) {
	return k.String(), nil
}

// UnmarshalYAML returns a PresharedKey from a YAML string
func (k *PresharedKey) UnmarshalYAML(f func(interface{}) error) error {
	b := new(string)
	if err := f(b); err == nil {
		key, err := hex.DecodeString(*b)
		if err != nil || len(key) != wgtypes.KeyLen {
			return fmt.Errorf("preshared key is of invalid size")
		}

		*k = key
		return nil
	}

	return fmt.Errorf("could not parse preshared key")
}

// MarshalYAML returns the YAML string representation of a PresharedKey
func (k PresharedKey) MarshalYAML() (interface{}, error) {
	return k.String(), nil
}
