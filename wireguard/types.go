package wireguard

import (
	nl "github.com/vishvananda/netlink"
)

const (
	// NetlinkName is the Netlink name for WireGuard
	NetlinkName = "wireguard"
)

// EmptyPSK is the byte representation used when no preshared key is set on a peer
var EmptyPSK = [32]byte{
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
}

// WGLink is a WireGuard link
type WGLink struct {
	nl.LinkAttrs
}

// Type retirns the WireGuard netlink type name
func (wg *WGLink) Type() string {
	return NetlinkName
}

// Attrs retirns the WireGuard netlink attrs
func (wg *WGLink) Attrs() *nl.LinkAttrs {
	return &wg.LinkAttrs
}
