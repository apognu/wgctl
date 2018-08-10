package wireguard

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/lunixbochs/struc"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
)

func GetDevice(ifname string) (*WGDevice, error) {
	attrs := map[uint16][]byte{DeviceName: nlenc.Bytes(ifname)}
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	resp, err := Request(CommandGetDevice, flags, attrs)
	if err != nil {
		return nil, err
	}

	dev := new(WGDevice)
	for _, m := range resp {
		attr, err := netlink.NewAttributeDecoder(m.Data)
		if err != nil {
			return nil, err
		}

		for attr.Next() {
			switch attr.Type() {
			case WGDeviceName:
				dev.Name = attr.String()
			case WGDeviceListenPort:
				dev.ListenPort = int(attr.Uint16())
			case WGDevicePublicKey:
				attr.Do(ParseKey(&dev.PublicKey))
			case WGDevicePrivateKey:
				attr.Do(ParseKey(&dev.PrivateKey))
			case WGDeviceFWMark:
				dev.FWMark = int(attr.Uint32())
			case WGDevicePeers:
				attr.Do(ParsePeers(&dev.Peers))
			}
		}
	}

	return dev, nil
}

func ParsePeers(devPeers *[]*WGPeer) func(b []byte) error {
	return func(b []byte) error {
		attrs, err := netlink.UnmarshalAttributes(b)
		if err != nil {
			return err
		}

		peers := make([]*WGPeer, len(attrs))
		for idx, data := range attrs {
			attr, err := netlink.NewAttributeDecoder(data.Data)
			if err != nil {
				return err
			}

			peer := new(WGPeer)

			for attr.Next() {
				switch attr.Type() {
				case WGPeerPublicKey:
					attr.Do(ParseKey(&peer.PublicKey))
				case WGPeerPresharedKey:
					attr.Do(ParsePresharedKey(&peer.PresharedKey))
				case WGPeerEndpoint:
					attr.Do(ParseEndpoint(&peer.Endpoint))
				case WGPeerAllowedIPs:
					attr.Do(ParseAllowedIPs(&peer.AllowedIPs))
				case WGPeerLastHandshake:
					attr.Do(ParseLastHandshake(&peer.LastHandshake))
				case WGPeerKeepaliveInterval:
					peer.KeepaliveInterval = int(attr.Uint16())
				case WGPeerRxBytes:
					peer.RXBytes = int(attr.Uint64())
				case WGPeerTxBytes:
					peer.TXBytes = int(attr.Uint64())
				}
			}

			peers[idx] = peer
		}

		*devPeers = peers

		return nil
	}
}

func ParseAllowedIPs(devIPs *PeerAllowedIPs) func(b []byte) error {
	return func(b []byte) error {
		attrs, err := netlink.UnmarshalAttributes(b)
		if err != nil {
			return err
		}

		ips := make(PeerAllowedIPs, len(attrs))
		for idx, data := range attrs {
			attr, err := netlink.NewAttributeDecoder(data.Data)
			if err != nil {
				return err
			}

			ip := new(WGAllowedIP)

			for attr.Next() {
				switch attr.Type() {
				case WGAllowedIPAddress:
					attr.Do(ParseIPAddress(&ip.Address))
				case WGAllowedIPCIDR:
					ip.CIDR = int(attr.Uint8())
				}
			}

			ips[idx] = ip
		}

		*devIPs = ips

		return nil
	}
}

func ParseKey(devKey *string) func(b []byte) error {
	return func(b []byte) error {
		*devKey = base64.StdEncoding.EncodeToString(b)

		return nil
	}
}

func ParsePresharedKey(devKey *string) func(b []byte) error {
	return func(b []byte) error {
		if fmt.Sprintf("%x", string(b)) != "0000000000000000000000000000000000000000000000000000000000000000" {
			*devKey = "yes"
		}

		return nil
	}
}

func ParseEndpoint(wgEndpoint **net.UDPAddr) func(b []byte) error {
	return func(b []byte) error {
		buf := bytes.NewBuffer(b)
		var endpoint interface{}

		if len(b) == 16 {
			endpoint = &WGSockAddr4{}
		} else {
			endpoint = &WGSockAddr6{}
		}
		err := struc.Unpack(buf, endpoint)
		if err != nil {
			return nil
		}

		if ep, ok := endpoint.(*WGSockAddr4); ok {
			*wgEndpoint = &net.UDPAddr{IP: net.IP(ep.Addr4), Port: int(ep.Port)}
		} else if ep, ok := endpoint.(*WGSockAddr6); ok {
			*wgEndpoint = &net.UDPAddr{IP: net.IP(ep.Addr6), Port: int(ep.Port)}
		}

		return nil
	}
}

func ParseIPAddress(endpoint **net.IP) func(b []byte) error {
	return func(b []byte) error {
		ip := net.IP(b)
		*endpoint = &ip

		return nil
	}
}

func ParseLastHandshake(t *time.Time) func(b []byte) error {
	return func(b []byte) error {
		buf := bytes.NewBuffer(b)
		var ti WGTimestamp
		struc.Unpack(buf, &ti)

		*t = time.Unix(int64(ti.Seconds), 0)

		return nil
	}
}
