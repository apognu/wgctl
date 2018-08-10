package wireguard

import (
	"fmt"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

func Request(cmd uint8, flags netlink.HeaderFlags, attrs map[uint16][]byte) ([]genetlink.Message, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	nlb, err := MarshalAttributes(attrs)
	if err != nil {
		return nil, err
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			Version: NetlinkVersion,
			Command: cmd,
		},
		Data: nlb,
	}

	resp, err := c.Execute(req, NetlinkFamily, flags)
	if err != nil {
		if err.Error() == "operation not supported" {
			return nil, fmt.Errorf("provided device is not a WireGuard interface")
		}
		return nil, err
	}

	return resp, nil
}

func MarshalAttributes(attrs map[uint16][]byte) ([]byte, error) {
	nla := make([]netlink.Attribute, len(attrs))
	idx := 0
	for k, v := range attrs {
		nla[idx] = netlink.Attribute{
			Type: k,
			Data: v,
		}

		idx++
	}

	return netlink.MarshalAttributes(nla)
}
