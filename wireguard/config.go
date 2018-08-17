package wireguard

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mdlayher/wireguardctrl/wgtypes"

	yaml "gopkg.in/yaml.v2"
)

// IPNet is an unmarshalable version of net.IPNet
type IPNet net.IPNet

// UDPAddr is an unmarshalable version of net.UDPAddr
type UDPAddr net.UDPAddr

// PrivateKey is an unmarshalable file path
type PrivateKey struct {
	Path string
	Data []byte
}

// Key is an unmarshalable ED25519 key
type Key []byte

// PresharedKey is un unmarshable preshared key
type PresharedKey []byte

// IPMask represents an IP address and its subnet mask, to be assigned to an interface
type IPMask struct {
	IP   net.IP
	Mask int
}

// String returns the classic CIDR representation of an IPMask (e.g. 192.168.0.1/24)
func (ip IPMask) String() string {
	return fmt.Sprintf("%s/%d", ip.IP.String(), ip.Mask)
}

// Config represents a YAML-encodable configuration for a WireGuard tunnel
type Config struct {
	Interface `yaml:"interface"`
	Peers     []*Peer `yaml:"peers"`
}

// Interface represents a YAML-encodable configuration for a WireGuard interface
type Interface struct {
	Description string     `yaml:"description"`
	Address     *IPMask    `yaml:"address"`
	ListenPort  int        `yaml:"listen_port"`
	PrivateKey  PrivateKey `yaml:"private_key"`
	FWMark      int        `yaml:"fwmark,omitempty"`
	PostUp      [][]string `yaml:"post_up,omitempty"`
	PreDown     [][]string `yaml:"pre_down,omitempty"`
	SetUpRoutes *bool      `yaml:"routes,omitempty"`
}

// Peer represents a YAML-encodable configuration for a WireGuard peer
type Peer struct {
	Description       string        `yaml:"description"`
	PublicKey         Key           `yaml:"public_key"`
	PresharedKey      *PresharedKey `yaml:"preshared_key,omitempty"`
	Endpoint          *UDPAddr      `yaml:"endpoint,omitempty"`
	AllowedIPS        []IPNet       `yaml:"allowed_ips,omitempty"`
	KeepaliveInterval time.Duration `yaml:"keepalive_interval,omitempty"`
}

// ParseConfig unmarshals a Config from a YAML string
func ParseConfig(instance string) (*Config, error) {
	path := fmt.Sprintf("%s/%s.yml", GetConfigPath(), instance)
	if _, err := os.Stat(instance); err == nil {
		path = instance
	}

	config, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not read configuration file: %s", err.Error())
	}

	return ParseConfigReader(config)
}

// ParseConfigReader unmarshals a Config from an io.Reader mapped to a YAML file
func ParseConfigReader(config io.Reader) (*Config, error) {
	c := new(Config)
	err := yaml.NewDecoder(config).Decode(c)
	if err != nil {
		return nil, fmt.Errorf("could not parse configuration file: %s", err.Error())
	}

	err = c.Check()
	if err != nil {
		return nil, fmt.Errorf("configuration check failed: %s", err.Error())
	}

	return c, nil
}

// Check verifies that all mandatory config directive have been given for a Config
// It also sets default values for some fields
func (c *Config) Check() error {
	if c.Interface.SetUpRoutes == nil {
		v := true
		c.Interface.SetUpRoutes = &v
	}
	if len(c.Interface.PrivateKey.Data) != wgtypes.KeyLen {
		return fmt.Errorf("'private_key' must be provided")
	}
	if c.Interface.ListenPort == 0 {
		return fmt.Errorf("'listen_port' must be provided")
	}

	for _, p := range c.Peers {
		if len(p.PublicKey) != wgtypes.KeyLen {
			return fmt.Errorf("peer's 'public_key' must be provided")
		}
	}

	return nil
}

// GetPeer finds a peer in a Config from its public key string representation
func (c *Config) GetPeer(publicKey string) *Peer {
	for _, p := range c.Peers {
		if p.PublicKey.String() == publicKey {
			return p
		}
	}
	return nil
}

// GetConfigPath returns the directory where the configuration files should be looked for
// This path can be overriden by setting the WGCTL_CONFIG_PATH environment variable
func GetConfigPath() string {
	if len(strings.TrimSpace(os.Getenv("WGCTL_CONFIG_PATH"))) > 0 {
		return strings.TrimSpace(os.Getenv("WGCTL_CONFIG_PATH"))
	}
	return "/etc/wireguard"
}

// GetInstanceFromArg returns the normalized name of a WireGuard tunnel instance (and interface)
func GetInstanceFromArg(path string) string {
	if _, err := os.Stat(path); err == nil {
		return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	return path
}

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
	return fmt.Sprintf("%s:%d", ip.IP.String(), ip.Port), nil
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

			*k = PrivateKey{
				Path: *b,
				Data: key,
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

// String returns the string repsentation of a private key
func (k *PrivateKey) String() string {
	return base64.StdEncoding.EncodeToString([]byte(k.Data))
}

// Bytes returns the byte representation of a private key
func (k *PrivateKey) Bytes() [wgtypes.KeyLen]byte {
	buf := bytes.NewReader(k.Data)
	out := new([32]byte)

	io.ReadFull(buf, out[:])

	return *out
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

// String returns the string representation of a public key
func (k *Key) String() string {
	return base64.StdEncoding.EncodeToString(*k)
}

// Bytes returns the byte representation of a public key
func (k *Key) Bytes() [wgtypes.KeyLen]byte {
	buf := bytes.NewReader(*k)
	out := new([32]byte)

	io.ReadFull(buf, out[:])

	return *out
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

// String returns the hex string representation of a preshared key
func (k *PresharedKey) String() string {
	if k == nil {
		return ""
	}
	return hex.EncodeToString([]byte(*k))
}

// Bytes returns the byte representation of a preshared key
func (k *PresharedKey) Bytes() [wgtypes.KeyLen]byte {
	buf := bytes.NewReader(*k)
	out := new([32]byte)

	io.ReadFull(buf, out[:])

	return *out
}
