package wireguard

import (
	"bytes"
	"net"

	"github.com/lunixbochs/struc"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func SetFWMark(instance string, fwmark int) error {
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge

	attrs := map[uint16][]byte{
		WGDeviceName:   nlenc.Bytes(instance),
		WGDeviceFWMark: nlenc.Uint32Bytes(uint32(fwmark)),
	}

	_, err := Request(CommandSetDevice, flags, attrs)
	if err != nil {
		return err
	}

	return nil
}

func ConfigureDevice(instance string, config *Config) {
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge

	attrs := map[uint16][]byte{
		WGDeviceName:       nlenc.Bytes(instance),
		WGDevicePrivateKey: config.Interface.PrivateKey,
		WGDeviceListenPort: nlenc.Uint16Bytes(uint16(config.Interface.ListenPort)),
		WGDeviceFWMark:     nlenc.Uint32Bytes(uint32(config.Interface.FWMark)),
	}

	if len(config.Peers) > 0 {
		peers := make(map[uint16][]byte, len(config.Peers))
		for idx, p := range config.Peers {
			peers[uint16(idx)] = ParsePeer(p)
		}

		nlb, err := MarshalAttributes(peers)
		if err != nil {
			logrus.Fatalf("could not marshal netlink peers attributes: %s", err.Error())
		}

		attrs[WGDevicePeers] = nlb
	}

	_, err := Request(CommandSetDevice, flags, attrs)
	if err != nil {
		logrus.Fatalf("could not configure device: %s", err.Error())
	}
}

func ParsePeer(p *Peer) []byte {
	attrs := map[uint16][]byte{
		WGPeerPublicKey: p.PublicKey,
	}

	if len(p.PresharedKey) > 0 {
		attrs[WGPeerPresharedKey] = p.PresharedKey
	}

	if p.KeepaliveInterval > 0 {
		attrs[WGPeerKeepaliveInterval] = nlenc.Uint16Bytes(uint16(p.KeepaliveInterval))
	}

	if p.Endpoint != nil {
		var endpoint interface{}
		if p.Endpoint.IP.To4() != nil {
			endpoint = WGSockAddr4{
				AddrFamily: unix.AF_INET,
				Addr4:      []byte(p.Endpoint.IP.To4()),
				Port:       uint16(p.Endpoint.Port),
			}
		} else {
			endpoint = WGSockAddr6{
				AddrFamily: unix.AF_INET6,
				Addr6:      []byte(p.Endpoint.IP.To16()),
				Port:       uint16(p.Endpoint.Port),
			}
		}

		b := new(bytes.Buffer)
		var err error
		if ep, ok := endpoint.(WGSockAddr4); ok {
			err = struc.Pack(b, &ep)
		} else if ep, ok := endpoint.(WGSockAddr6); ok {
			err = struc.Pack(b, &ep)
		}
		if err != nil {
			logrus.Fatalf(err.Error())
		}

		attrs[WGPeerEndpoint] = b.Bytes()

		if len(p.AllowedIPS) > 0 {
			aips := make(map[uint16][]byte, len(p.AllowedIPS))
			for idx, aip := range p.AllowedIPS {
				aips[uint16(idx)] = ParseAllowedIP(net.IPNet(*aip))
			}

			nlb, err := MarshalAttributes(aips)
			if err != nil {
				logrus.Fatalf("could not marshal netlink peers attributes: %s", err.Error())
			}

			attrs[WGPeerAllowedIPs] = nlb
		}
	}

	nlb, err := MarshalAttributes(attrs)
	if err != nil {
		logrus.Fatalf("could not marshal netlink peer attributes: %s", err.Error())
	}

	return nlb
}

func ParseAllowedIP(ip net.IPNet) []byte {
	mask, _ := ip.Mask.Size()

	var attrs map[uint16][]byte
	if ip.IP.To4() != nil {
		attrs = map[uint16][]byte{
			WGAllowedIPFamily:  nlenc.Uint16Bytes(unix.AF_INET),
			WGAllowedIPAddress: ip.IP.To4(),
			WGAllowedIPCIDR:    nlenc.Uint8Bytes(uint8(mask)),
		}
	} else {
		attrs = map[uint16][]byte{
			WGAllowedIPFamily:  nlenc.Uint16Bytes(unix.AF_INET6),
			WGAllowedIPAddress: ip.IP.To16(),
			WGAllowedIPCIDR:    nlenc.Uint8Bytes(uint8(mask)),
		}
	}

	nlb, err := MarshalAttributes(attrs)
	if err != nil {
		logrus.Fatalf("could not marshal netlink peer attributes: %s", err.Error())
	}

	return nlb
}
