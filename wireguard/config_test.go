package wireguard

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const fullConfigYAML = `
interface:
  description: Lorem ipsum dolor sit amet
  address: 1.2.3.4/24
  listen_port: 23456
  private_key: /tmp/testing.key
  fwmark: 12345
  routes: false
peers:
  - description: 'Peer #1'
    public_key: 7X78dxEtCqCzVTxFYnxCcjxviI1vzeTl13yq+7rdPD4=
    preshared_key: 4dcc2c74b23387db09bfc635f2cded65eb375db9bd55a64a8c5f18d26441dbc1
    endpoint: 4.3.2.1:45000
    allowed_ips:
      - 20.30.40.50/32
      - 50.40.30.20/24
    keepalive_interval: 10
  - description: 'Peer #2'
    public_key: 4X78dxEtCqCzVTxFYnxCcjxviI1vzeTl13yq+7rdPD4=
    endpoint: 4.3.2.1:45001
    allowed_ips:
      - 20.30.40.50/32
      - 50.40.30.20/24
    keepalive_interval: 10
`

const minimalConfigYAML = `
interface:
  address: 1.2.3.4/24
  listen_port: 23456
  private_key: /tmp/testing.key
`

const minimalConfigWithPeerYAML = `
interface:
  address: 1.2.3.4/24
  listen_port: 23456
  private_key: /tmp/testing.key
peers:
  - public_key: 7X78dxEtCqCzVTxFYnxCcjxviI1vzeTl13yq+7rdPD4=
`

const configWithInvalidPeerKey = `
interface:
  address: 1.2.3.4/24
  listen_port: 23456
  private_key: /tmp/testing.key
peers:
  - public_key: 7X78dxEtCqCzVTxFYnxCcjxviI1vzeTl13yq+7rdPD
`

const configWithEmptyPeerKey = `
interface:
  address: 1.2.3.4/24
  listen_port: 23456
  private_key: /tmp/testing.key
peers:
  - {}
`

func createPKey(t *testing.T) {
	err := ioutil.WriteFile("/tmp/testing.key", []byte("7X78dxEtCqCzVTxFYnxCcjxviI1vzeTl13yq+7rdPD4="), 0600)
	if err != nil {
		t.Fatalf("could not create temporary private key: %s", err.Error())
	}
}

func Test_ParseFullConfig(t *testing.T) {
	createPKey(t)
	c, err := ParseConfigReader(bytes.NewReader([]byte(fullConfigYAML)))
	assert.Nil(t, err)

	addr, sub, _ := net.ParseCIDR("1.2.3.4/24")

	assert.Equal(t, "Lorem ipsum dolor sit amet", c.Interface.Description)
	assert.Equal(t, addr, c.Interface.Address.IP)
	assert.Equal(t, 24, c.Interface.Address.Mask)
	assert.Equal(t, 23456, c.Interface.ListenPort)
	assert.Equal(t, "7X78dxEtCqCzVTxFYnxCcjxviI1vzeTl13yq+7rdPD4=", c.Interface.PrivateKey.String())
	assert.Equal(t, 12345, c.Interface.FWMark)
	assert.Equal(t, false, *c.Interface.SetUpRoutes)

	assert.Equal(t, 2, len(c.Peers))

	ip, port, _ := net.SplitHostPort("4.3.2.1:45000")
	p, _ := strconv.Atoi(port)
	ep := UDPAddr{IP: net.ParseIP(ip), Port: p}

	assert.Equal(t, "Peer #1", c.Peers[0].Description)
	assert.Equal(t, "7X78dxEtCqCzVTxFYnxCcjxviI1vzeTl13yq+7rdPD4=", c.Peers[0].PublicKey.String())
	assert.Equal(t, "4dcc2c74b23387db09bfc635f2cded65eb375db9bd55a64a8c5f18d26441dbc1", c.Peers[0].PresharedKey.String())
	assert.Equal(t, ep, *c.Peers[0].Endpoint)
	assert.Equal(t, 2, len(c.Peers[0].AllowedIPS))

	_, sub, _ = net.ParseCIDR("20.30.40.50/32")

	assert.Equal(t, IPNet(*sub), c.Peers[0].AllowedIPS[0])
	assert.Equal(t, time.Duration(10), c.Peers[0].KeepaliveInterval)
}

func Test_ParseMinimalConfig(t *testing.T) {
	createPKey(t)
	c, err := ParseConfigReader(bytes.NewReader([]byte(minimalConfigYAML)))

	assert.Nil(t, err)
	assert.Equal(t, true, *c.Interface.SetUpRoutes)
	assert.Equal(t, 0, len(c.Peers))
}

func Test_ParseMinimalConfigWithPeer(t *testing.T) {
	createPKey(t)
	c, err := ParseConfigReader(bytes.NewReader([]byte(minimalConfigWithPeerYAML)))

	assert.Nil(t, err)
	assert.Equal(t, true, *c.Interface.SetUpRoutes)
	assert.Equal(t, 1, len(c.Peers))
	assert.Equal(t, "", c.Peers[0].PresharedKey.String())
	assert.Equal(t, 0*time.Second, c.Peers[0].KeepaliveInterval)
}

func Test_ParseConfigWithInvalidPeerKey(t *testing.T) {
	createPKey(t)
	_, err := ParseConfigReader(bytes.NewReader([]byte(configWithInvalidPeerKey)))

	assert.NotNil(t, err)
}

func Test_ParseConfigWithEmptyPeerKey(t *testing.T) {
	createPKey(t)
	_, err := ParseConfigReader(bytes.NewReader([]byte(configWithEmptyPeerKey)))

	assert.NotNil(t, err)
}

func Test_CheckConfig(t *testing.T) {
	c := &Config{}
	assert.NotEqual(nil, c.Check(), "")

	k, _ := base64.StdEncoding.DecodeString("7X78dxEtCqCzVTxFYnxCcjxviI1vzeTl13yq+7rdPD4=")

	c = &Config{Interface: Interface{PrivateKey: PrivateKey{Data: k}}}
	assert.NotEqual(nil, c.Check(), "")

	c = &Config{Interface: Interface{ListenPort: 10000}}
	assert.NotEqual(nil, c.Check(), "")

	ipnet := IPMask{IP: net.ParseIP("1.2.3.4"), Mask: 24}
	c = &Config{Interface: Interface{Address: &ipnet}}
	assert.NotEqual(nil, c.Check(), "")

	c = &Config{Interface: Interface{Address: &ipnet, ListenPort: 10000}, Peers: []*Peer{&Peer{}}}
	assert.NotEqual(nil, c.Check(), "")

	c = &Config{Interface: Interface{PrivateKey: PrivateKey{Data: k}, Address: &ipnet, ListenPort: 10000}, Peers: []*Peer{&Peer{PublicKey: k}}}
	assert.Equal(t, nil, c.Check(), "")
}

func Test_ParseConfigNoExistFile(t *testing.T) {
	_, err := ParseConfig("notexistingconfig")
	assert.NotNil(t, err)

	_, err = ParseConfig("/etc/wg/notexistingconfig.yml")
	assert.NotNil(t, err)
}

func Test_ParseConfig(t *testing.T) {
	ioutil.WriteFile("/etc/wireguard/existingconfig.yml", []byte(fullConfigYAML), 0400)

	_, err := ParseConfig("existingconfig")
	assert.Nil(t, err)

	_, err = ParseConfig("/etc/wireguard/existingconfig.yml")
	assert.Nil(t, err)

	os.Remove("/etc/wireguard/existingconfig.yml")
}

func Test_GetPeer(t *testing.T) {
	createPKey(t)
	c, err := ParseConfigReader(bytes.NewReader([]byte(fullConfigYAML)))

	assert.Nil(t, err)
	assert.Nil(t, c.GetPeer("loremipsum"))

	p := c.GetPeer("7X78dxEtCqCzVTxFYnxCcjxviI1vzeTl13yq+7rdPD4=")
	assert.NotNil(t, p)
	assert.Equal(t, "7X78dxEtCqCzVTxFYnxCcjxviI1vzeTl13yq+7rdPD4=", p.PublicKey.String())
}

func Test_GetInstanceFromArg(t *testing.T) {
	assert.Equal(t, "instance", GetInstanceFromArg("instance"))
	assert.Equal(t, "hosts", GetInstanceFromArg("/etc/hosts"))
}

func Test_GetConfigPath(t *testing.T) {
	os.Setenv("WGCTL_CONFIG_PATH", "")
	assert.Equal(t, "/etc/wireguard", GetConfigPath())

	os.Setenv("WGCTL_CONFIG_PATH", "/my/wireguard/config")
	assert.Equal(t, "/my/wireguard/config", GetConfigPath())
}

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
	assert.Equal(t, "127.0.0.1", ip.IP.String())
	assert.Equal(t, 8, ip.Mask)
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
	assert.Equal(t, "127.0.0.0", ip.IP.String())
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
	assert.Equal(t, "127.0.0.1", addr.IP.String())
	assert.Equal(t, 12345, addr.Port)
}

func Test_UnmarshalPrivateKeyFile(t *testing.T) {
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
