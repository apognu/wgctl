package lib

import (
	"bytes"
	"encoding/base64"
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

const fullIPv6ConfigYAML = `
interface:
  description: Lorem ipsum dolor sit amet
  address: 2001:db8:0:12::2:1/64
  listen_port: 23456
  private_key: /tmp/testing.key
  fwmark: 12345
  routes: false
peers:
  - description: 'Peer #1'
    public_key: 7X78dxEtCqCzVTxFYnxCcjxviI1vzeTl13yq+7rdPD4=
    preshared_key: 4dcc2c74b23387db09bfc635f2cded65eb375db9bd55a64a8c5f18d26441dbc1
    endpoint: '[fe80::c002:37ff:fe6C:0]:45000'
    allowed_ips:
      - fe80::1234:1/48
      - fe80::1234:2/128
    keepalive_interval: 10
  - description: 'Peer #2'
    public_key: 4X78dxEtCqCzVTxFYnxCcjxviI1vzeTl13yq+7rdPD4=
    endpoint: '[fe80:b00b:cafe::10]:45001'
    allowed_ips:
      - fe80::1234:3/48
      - fe80::1234:4/128
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

	addr, _, _ := net.ParseCIDR("1.2.3.4/24")

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

	_, sub, _ := net.ParseCIDR("20.30.40.50/32")

	assert.Equal(t, IPNet(*sub), c.Peers[0].AllowedIPS[0])
	assert.Equal(t, time.Duration(10), c.Peers[0].KeepaliveInterval)
}

func Test_ParseFullIPv6Config(t *testing.T) {
	createPKey(t)
	c, err := ParseConfigReader(bytes.NewReader([]byte(fullIPv6ConfigYAML)))
	assert.Nil(t, err)

	addr, _, _ := net.ParseCIDR("2001:db8:0:12::2:1/64")

	assert.Equal(t, "Lorem ipsum dolor sit amet", c.Interface.Description)
	assert.Equal(t, addr, c.Interface.Address.IP)
	assert.Equal(t, 64, c.Interface.Address.Mask)
	assert.Equal(t, 23456, c.Interface.ListenPort)
	assert.Equal(t, "7X78dxEtCqCzVTxFYnxCcjxviI1vzeTl13yq+7rdPD4=", c.Interface.PrivateKey.String())
	assert.Equal(t, 12345, c.Interface.FWMark)
	assert.Equal(t, false, *c.Interface.SetUpRoutes)

	assert.Equal(t, 2, len(c.Peers))

	ip, port, _ := net.SplitHostPort("[fe80::c002:37ff:fe6C:0]:45000")
	p, _ := strconv.Atoi(port)
	ep := UDPAddr{IP: net.ParseIP(ip), Port: p}

	assert.Equal(t, "Peer #1", c.Peers[0].Description)
	assert.Equal(t, "7X78dxEtCqCzVTxFYnxCcjxviI1vzeTl13yq+7rdPD4=", c.Peers[0].PublicKey.String())
	assert.Equal(t, "4dcc2c74b23387db09bfc635f2cded65eb375db9bd55a64a8c5f18d26441dbc1", c.Peers[0].PresharedKey.String())
	assert.Equal(t, ep, *c.Peers[0].Endpoint)
	assert.Equal(t, 2, len(c.Peers[0].AllowedIPS))

	_, sub, _ := net.ParseCIDR("fe80::1234:1/48")

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
	assert.NotEqual(t, nil, c.Check())

	k, _ := base64.StdEncoding.DecodeString("7X78dxEtCqCzVTxFYnxCcjxviI1vzeTl13yq+7rdPD4=")

	c = &Config{Interface: Interface{PrivateKey: NewPrivateKey(k)}}
	assert.NotNil(t, c.Check())

	c = &Config{Interface: Interface{ListenPort: 10000}}
	assert.NotNil(t, c.Check())

	ipnet := IPMask{IP: net.ParseIP("1.2.3.4"), Mask: 24}
	c = &Config{Interface: Interface{Address: &ipnet}}
	assert.NotNil(t, c.Check())

	c = &Config{Interface: Interface{PrivateKey: NewPrivateKey(k), ListenPort: 10000}, Peers: []*Peer{{Description: "YOP"}}}
	assert.NotNil(t, c.Check())

	c = &Config{Interface: Interface{PrivateKey: NewPrivateKey(k), Address: &ipnet, ListenPort: 10000}, Peers: []*Peer{{PublicKey: k}}}
	assert.Nil(t, c.Check())
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

func Test_KeyToBytes(t *testing.T) {
	bk := GetKey(t)
	key := Key(bk)
	k := key.Bytes()

	assert.Equal(t, len(k), len(bk))
	assert.Equal(t, k[:], bk)
}

func Test_PrivateKeyToBytes(t *testing.T) {
	key, _ := GeneratePrivateKey()
	bk := key.Bytes()

	assert.Equal(t, len(key.Data), len(bk))
	assert.Equal(t, key.Data, bk)
}

func Test_PresharedKeyToBytes(t *testing.T) {
	key := GetPSK(t)
	bk := key.Bytes()

	assert.Equal(t, len(bk), len([]byte(*key)))
	assert.Equal(t, []byte(*key), bk[:])
}

func Test_IPMaskTransforms(t *testing.T) {
	ip, sub, _ := net.ParseCIDR("192.168.255.40/16")
	mask, _ := sub.Mask.Size()
	ipmask := IPMask{IP: ip, Mask: mask}

	assert.Equal(t, "192.168.255.40/16", ipmask.String())
}
