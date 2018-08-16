package wireguard

import (
	"fmt"
	"net"

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

// ConfigureDevice sets all WireGuard parameter in a Config
func ConfigureDevice(instance string, config *Config) error {
	nlcl, err := wireguardctrl.New()
	if err != nil {
		return fmt.Errorf("could not create wireguard client: %s", err.Error())
	}

	priv := wgtypes.Key(config.Interface.PrivateKey.Bytes())

	c := wgtypes.Config{
		PrivateKey:   &priv,
		ListenPort:   &config.Interface.ListenPort,
		FirewallMark: &config.Interface.FWMark,
	}

	if len(config.Peers) > 0 {
		peers := make([]wgtypes.PeerConfig, len(config.Peers))
		for idx, p := range config.Peers {
			peers[idx] = ParsePeer(p)
		}

		c.Peers = peers
	}

	err = nlcl.ConfigureDevice(instance, c)
	if err != nil {
		return fmt.Errorf("could not configure wireguard client: %s", err.Error())
	}

	return nil
}

// ParsePeer creates a Netlink-compatible view of a peer
func ParsePeer(p *Peer) wgtypes.PeerConfig {
	peer := wgtypes.PeerConfig{
		PublicKey: wgtypes.Key(p.PublicKey.Bytes()),
	}

	if len(p.PresharedKey) > 0 {
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
