package wireguard

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

type NetlinkAttribute uint16

const (
	_ = iota
	NLDeviceIndex
	NLDeviceName
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

const (
	_ = iota
	NLWGPeerPublicKey
	NLWGPeerPresharedKey
	_
	NLWGPeerEndpoint
	NLWGPeerKeepaliveInterval
	NLWGPeerLastHandshake
	NLWGPeerRxBytes
	NLWGPeerTxBytes
	NLWGPeerAllowedIPs
)

const (
	_ = iota
	NLWGAllowedIPFamily
	NLWGAllowedIPAddress
	NLWGAllowedIPCIDR
)
