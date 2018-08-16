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
	"strconv"
	"strings"
	"time"

	"github.com/mdlayher/wireguardctrl/wgtypes"

	"github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
)

type IPNet net.IPNet
type UDPAddr net.UDPAddr
type PrivateKeyFile []byte
type Key []byte
type PresharedKey []byte

type Config struct {
	Interface `yaml:"interface"`
	Peers     []*Peer `yaml:"peers"`
}

type Interface struct {
	Description string         `yaml:"description"`
	Address     *IPNet         `yaml:"address"`
	ListenPort  int            `yaml:"listen_port"`
	PrivateKey  PrivateKeyFile `yaml:"private_key"`
	FWMark      int            `yaml:"fwmark"`
	PostUp      [][]string     `yaml:"post_up"`
	PreDown     [][]string     `yaml:"pre_down"`
	SetUpRoutes *bool          `yaml:"routes"`
}

type Peer struct {
	Description       string        `yaml:"description"`
	PublicKey         Key           `yaml:"public_key"`
	PresharedKey      PresharedKey  `yaml:"preshared_key"`
	Endpoint          *UDPAddr      `yaml:"endpoint"`
	AllowedIPS        []IPNet       `yaml:"allowed_ips"`
	KeepaliveInterval time.Duration `yaml:"keepalive_interval"`
}

func ParseConfig(instance string) *Config {
	path := fmt.Sprintf("%s/%s.yml", GetConfigPath(), instance)
	if _, err := os.Stat(instance); err == nil {
		path = instance
	}

	config, err := os.Open(path)
	if err != nil {
		logrus.Fatalf("could not read configuration file: %s", err.Error())
	}

	return ParseConfigReader(config)
}

func ParseConfigReader(config io.Reader) *Config {
	c := new(Config)
	err := yaml.NewDecoder(config).Decode(c)
	if err != nil {
		logrus.Fatalf("could not parse configuration file: %s", err.Error())
	}

	err = c.Check()
	if err != nil {
		logrus.Fatalf("configuration check failed: %s", err.Error())
	}

	return c
}

func (c *Config) Check() error {
	if c.Interface.SetUpRoutes == nil {
		v := true
		c.Interface.SetUpRoutes = &v
	}
	if len(c.Interface.PrivateKey) != wgtypes.KeyLen {
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

func (c *Config) GetPeer(publicKey string) *Peer {
	for _, p := range c.Peers {
		if p.PublicKey.String() == publicKey {
			return p
		}
	}
	return nil
}

func GetConfigPath() string {
	if len(strings.TrimSpace(os.Getenv("WGCTL_CONFIG_PATH"))) > 0 {
		return strings.TrimSpace(os.Getenv("WGCTL_CONFIG_PATH"))
	}
	return "/etc/wireguard"
}

func GetInstanceFromArg(path string) string {
	if _, err := os.Stat(path); err == nil {
		return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	return path
}

func (ip *IPNet) UnmarshalYAML(f func(interface{}) error) error {
	b := new(string)
	if err := f(b); err != nil {
		return fmt.Errorf("could not parse IP address ")
	}

	if _, cidr, err := net.ParseCIDR(*b); err == nil {
		*ip = IPNet(*cidr)
		return nil
	}

	return fmt.Errorf("could not parse IP address! %s", *b)
}

func (ip *UDPAddr) UnmarshalYAML(f func(interface{}) error) error {
	b := new(string)
	if err := f(b); err != nil {
		return fmt.Errorf("could not parse IP address")
	}

	if host, port, err := net.SplitHostPort(*b); err == nil {
		h := net.ParseIP(host)
		p, err := strconv.Atoi(port)
		if err != nil {
			return fmt.Errorf("could not parse port")
		}

		*ip = UDPAddr{IP: h, Port: p}
		return nil
	}

	return fmt.Errorf("could not parse IP address: %s", *b)
}

func (key *PrivateKeyFile) UnmarshalYAML(f func(interface{}) error) error {
	b := new(string)
	if err := f(b); err != nil {
		return fmt.Errorf("could not parse private key path")
	}

	if k, err := ioutil.ReadFile(*b); err == nil {
		if err != nil {
			return fmt.Errorf("could not read private key")
		}

		b64key := strings.TrimSpace(string(k))
		k, err = base64.StdEncoding.DecodeString(b64key)
		if err != nil || len(k) != wgtypes.KeyLen {
			return fmt.Errorf("key is of invalid size")
		}

		*key = k
		return nil
	}

	return fmt.Errorf("could not open private key file")
}

func (k *PrivateKeyFile) String() string {
	return base64.StdEncoding.EncodeToString([]byte(*k))
}

func (k *PrivateKeyFile) Bytes() [wgtypes.KeyLen]byte {
	buf := bytes.NewReader(*k)
	out := new([32]byte)

	io.ReadFull(buf, out[:])

	return *out
}

func (key *Key) UnmarshalYAML(f func(interface{}) error) error {
	b := new(string)
	if err := f(b); err != nil {
		return fmt.Errorf("could not parse private key path")
	}

	b64key := strings.TrimSpace(*b)
	k, err := base64.StdEncoding.DecodeString(b64key)
	if err != nil || len(k) != wgtypes.KeyLen {
		return fmt.Errorf("key is of invalid size")
	}

	*key = k
	return nil
}

func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k)
}

func (k Key) Bytes() [wgtypes.KeyLen]byte {
	buf := bytes.NewReader(k)
	out := new([32]byte)

	io.ReadFull(buf, out[:])

	return *out
}

func (key *PresharedKey) UnmarshalYAML(f func(interface{}) error) error {
	b := new(string)
	if err := f(b); err != nil {
		return fmt.Errorf("could not parse private key path")
	}

	k, err := hex.DecodeString(*b)
	if err != nil || len(k) != wgtypes.KeyLen {
		return fmt.Errorf("key is of invalid size")
	}

	*key = k
	return nil
}

func (k *PresharedKey) String() string {
	return hex.EncodeToString([]byte(*k))
}

func (k PresharedKey) Bytes() [wgtypes.KeyLen]byte {
	buf := bytes.NewReader(k)
	out := new([32]byte)

	io.ReadFull(buf, out[:])

	return *out
}
