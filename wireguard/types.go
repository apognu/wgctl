package wireguard

import (
	nl "github.com/vishvananda/netlink"
)

const (
	NetlinkName = "wireguard"
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
