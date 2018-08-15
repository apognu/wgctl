package wireguard

import (
	nl "github.com/vishvananda/netlink"
)

const (
	NetlinkName    = "wireguard"
	NetlinkVersion = 1

	CommandGetDevice = 0
	CommandSetDevice = 1

	KeyLength = 32
)

var (
	NetlinkFamily uint16 = 0
)

const (
	_ = iota
	_
	NLWGDeviceName
	NLWGDevicePrivateKey
	NLWGDevicePublicKey
	_
	NLWGDeviceListenPort
	NLWGDeviceFWMark
	NLWGDevicePeers
)

var EmptyPSK = [32]byte{
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
}

type WGLink struct {
	nl.LinkAttrs
}

func (wg *WGLink) Type() string {
	return "wireguard"
}

func (wg *WGLink) Attrs() *nl.LinkAttrs {
	return &wg.LinkAttrs
}
