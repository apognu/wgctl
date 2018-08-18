package wireguard

import (
	"fmt"
	"net"

	"github.com/apognu/wgctl/lib"
	"github.com/mdlayher/wireguardctrl"
	"github.com/mdlayher/wireguardctrl/wgtypes"
	"github.com/sirupsen/logrus"
)

// SetFWMark changes the firewall mark on a specified WireGuard device
func SetFWMark(instance string, fwmark int) error {
	nlcl, err := wireguardctrl.New()
	if err != nil {
		logrus.Fatalf("could not create wireguard client: %s", err.Error())
	}

	err = nlcl.ConfigureDevice(instance, wgtypes.Config{FirewallMark: &fwmark})

	return err
}

// SetDevice sets individual properties on a wireguard device without creating low-level
// interfaces.
func SetDevice(instance string, config wgtypes.Config, replacePeers bool) error {
	nlcl, err := wireguardctrl.New()
	if err != nil {
		return fmt.Errorf("could not create wireguard client: %s", err.Error())
	}

	config.ReplacePeers = replacePeers

	err = nlcl.ConfigureDevice(instance, config)
	if err != nil {
		return fmt.Errorf("could not configure wireguard client: %s", err.Error())
	}

	return nil
}

// ConfigureDevice sets all WireGuard parameter in a Config
func ConfigureDevice(instance string, config *lib.Config, replacePeers bool) error {
	priv := wgtypes.Key(config.Interface.PrivateKey.Bytes())

	c := wgtypes.Config{
		PrivateKey:   &priv,
		ListenPort:   &config.Interface.ListenPort,
		FirewallMark: &config.Interface.FWMark,
		ReplacePeers: replacePeers,
	}

	if len(config.Peers) > 0 {
		peers := make([]wgtypes.PeerConfig, len(config.Peers))
		for idx, p := range config.Peers {
			peers[idx] = ParsePeer(p)
		}

		c.Peers = peers
	}

	return SetDevice(instance, c, true)
}

// ParsePeer creates a Netlink-compatible view of a peer
func ParsePeer(p *lib.Peer) wgtypes.PeerConfig {
	peer := wgtypes.PeerConfig{
		PublicKey: wgtypes.Key(p.PublicKey.Bytes()),
	}

	if p.PresharedKey != nil && len(*p.PresharedKey) > 0 {
		psk := wgtypes.Key(p.PresharedKey.Bytes())
		peer.PresharedKey = &psk
	}

	if p.KeepaliveInterval > 0 {
		peer.PersistentKeepaliveInterval = &p.KeepaliveInterval
	}

	if p.Endpoint != nil {
		addr := net.UDPAddr(*p.Endpoint)
		peer.Endpoint = &addr
	}

	if len(p.AllowedIPS) > 0 {
		ips := make([]net.IPNet, len(p.AllowedIPS))
		for idx, ip := range p.AllowedIPS {
			ips[idx] = net.IPNet(ip)
		}

		peer.AllowedIPs = ips
	}

	return peer
}
