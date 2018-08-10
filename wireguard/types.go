package wireguard

import (
	"net"
	"time"

	nl "github.com/vishvananda/netlink"
)

type WireGuardLink struct {
	nl.LinkAttrs
}

func (wg *WireGuardLink) Type() string {
	return "wireguard"
}

func (wg *WireGuardLink) Attrs() *nl.LinkAttrs {
	return &wg.LinkAttrs
}

type WGDevice struct {
	Name       string
	ListenPort int
	PublicKey  string
	PrivateKey string
	FWMark     int

	Peers []*WGPeer
}

type WGPeer struct {
	PublicKey         string
	PresharedKey      string
	Endpoint          *net.UDPAddr
	AllowedIPs        PeerAllowedIPs
	LastHandshake     time.Time
	KeepaliveInterval int
	RXBytes           int
	TXBytes           int
}

type PeerAllowedIPs []*WGAllowedIP

type WGAllowedIP struct {
	Address *net.IP
	CIDR    int
}

type WGSockAddr4 struct {
	AddrFamily int     `struc:"int16,little"`
	Port       uint16  `struc:"int16,big"`
	Addr4      []byte  `struc:"[4]byte,big"`
	Padding    [8]byte `struc:"[8]byte"`
}

type WGSockAddr6 struct {
	AddrFamily int     `struc:"int16,little"`
	Port       uint16  `struc:"int16,big"`
	Addr4      [4]byte `struc:"[4]byte"`
	Addr6      []byte  `struc:"[16]byte,big"`
	Padding    [4]byte `struc:"[4]byte"`
}

type WGTimestamp struct {
	Seconds uint32 `struc:"uint32,little"`
}
