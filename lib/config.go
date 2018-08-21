package lib

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
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
	Data [wgtypes.KeyLen]byte
}

// NewPrivateKey retirns a PrivateKey from a []byte
func NewPrivateKey(bk []byte) PrivateKey {
	k := new([wgtypes.KeyLen]byte)
	copy(k[:], bk)

	return PrivateKey{Data: *k}
}

// Bytes returns the byte representation of a private key
func (k *PrivateKey) Bytes() [wgtypes.KeyLen]byte {
	buf := bytes.NewReader(k.Data[:])
	out := new([32]byte)

	io.ReadFull(buf, out[:])

	return *out
}

// String returns the string repsentation of a private key
func (k *PrivateKey) String() string {
	return base64.StdEncoding.EncodeToString(k.Data[:])
}

// Key is an unmarshalable ED25519 key
type Key []byte

// Bytes returns the byte representation of a public key
func (k *Key) Bytes() [wgtypes.KeyLen]byte {
	buf := bytes.NewReader(*k)
	out := new([32]byte)

	io.ReadFull(buf, out[:])

	return *out
}

// String returns the string representation of a public key
func (k *Key) String() string {
	return base64.StdEncoding.EncodeToString(*k)
}

// PresharedKey is un unmarshable preshared key
type PresharedKey []byte

// Bytes returns the byte representation of a preshared key
func (k *PresharedKey) Bytes() [wgtypes.KeyLen]byte {
	buf := bytes.NewReader(*k)
	out := new([32]byte)

	io.ReadFull(buf, out[:])

	return *out
}

// String returns the hex string representation of a preshared key
func (k *PresharedKey) String() string {
	if k == nil {
		return ""
	}
	return hex.EncodeToString([]byte(*k))
}

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
	if c.Interface.PrivateKey.Data == EmptyPSK {
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
// This path can be overridden by setting the WGCTL_CONFIG_PATH environment variable
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
