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
	DeviceIndex
	DeviceName
)

const (
	_ = iota
	_
	WGDeviceName
	WGDevicePrivateKey
	WGDevicePublicKey
	_
	WGDeviceListenPort
	WGDeviceFWMark
	WGDevicePeers
)

const (
	_ = iota
	WGPeerPublicKey
	WGPeerPresharedKey
	_
	WGPeerEndpoint
	WGPeerKeepaliveInterval
	WGPeerLastHandshake
	WGPeerRxBytes
	WGPeerTxBytes
	WGPeerAllowedIPs
)

const (
	_ = iota
	WGAllowedIPFamily
	WGAllowedIPAddress
	WGAllowedIPCIDR
)
