package wireguard

import (
	"net"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/mdlayher/wireguardctrl"
	"github.com/mdlayher/wireguardctrl/wgtypes"
	"github.com/sirupsen/logrus"
)

func SetFWMark(instance string, fwmark int) error {
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge

	attrs := map[uint16][]byte{
		NLWGDeviceName:   nlenc.Bytes(instance),
		NLWGDeviceFWMark: nlenc.Uint32Bytes(uint32(fwmark)),
	}

	_, err := Request(CommandSetDevice, flags, attrs)
	if err != nil {
		return err
	}

	return nil
}

func ConfigureDevice(instance string, config *Config) {
	nlcl, err := wireguardctrl.New()
	if err != nil {
		logrus.Fatalf("could not create wireguard client: %s", err.Error())
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

	nlcl.ConfigureDevice(instance, c)
}

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
