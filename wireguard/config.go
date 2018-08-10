package wireguard

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
)

type IPNet net.IPNet
type TCPAddr net.TCPAddr
type PrivateKeyFile []byte
type Key []byte
type PresharedKey []byte

type Config struct {
	Description string `yaml:"description"`
	Interface   struct {
		Address    *IPNet         `yaml:"address"`
		ListenPort int            `yaml:"listen_port"`
		PrivateKey PrivateKeyFile `yaml:"private_key"`
		FWMark     int            `yaml:"fwmark"`
	} `yaml:"interface"`
	Peers []*Peer `yaml:"peers"`
}

type Peer struct {
	Description       string       `yaml:"description"`
	PublicKey         Key          `yaml:"public_key"`
	PresharedKey      PresharedKey `yaml:"preshared_key"`
	Endpoint          *TCPAddr     `yaml:"endpoint"`
	AllowedIPS        []*IPNet     `yaml:"allowed_ips"`
	KeepaliveInterval int          `yaml:"keepalive_interval"`
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

func (ip *TCPAddr) UnmarshalYAML(f func(interface{}) error) error {
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

		*ip = TCPAddr{IP: h, Port: p}
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
		if err != nil || len(k) != KeyLength {
			return fmt.Errorf("key is of invalid size")
		}

		*key = k
		return nil
	}

	return fmt.Errorf("could not open private key file")
}

func (key *Key) UnmarshalYAML(f func(interface{}) error) error {
	b := new(string)
	if err := f(b); err != nil {
		return fmt.Errorf("could not parse private key path")
	}

	b64key := strings.TrimSpace(*b)
	k, err := base64.StdEncoding.DecodeString(b64key)
	if err != nil || len(k) != KeyLength {
		return fmt.Errorf("key is of invalid size")
	}

	*key = k
	return nil
}

func (key *PresharedKey) UnmarshalYAML(f func(interface{}) error) error {
	b := new(string)
	if err := f(b); err != nil {
		return fmt.Errorf("could not parse private key path")
	}

	k, err := hex.DecodeString(*b)
	if err != nil || len(k) != KeyLength {
		return fmt.Errorf("key is of invalid size")
	}

	*key = k
	return nil
}

func (c *Config) Check() {
	if len(c.Interface.PrivateKey) != KeyLength {
		logrus.Fatalf("configuration check failed: 'private_key' must be provided")
	}
	if c.Interface.ListenPort == 0 {
		logrus.Fatalf("configuration check failed: 'listen_port' must be provided")
	}

	for _, p := range c.Peers {
		if len(p.PublicKey) != KeyLength {
			logrus.Fatalf("configuration check failed: peer's 'public_key' must be provided")
		}
	}
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

	c := new(Config)
	err = yaml.NewDecoder(config).Decode(c)
	if err != nil {
		logrus.Fatalf("could not parse configuration file: %s", err.Error())
	}

	c.Check()

	return c
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
