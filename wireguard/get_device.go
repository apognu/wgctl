package wireguard

import (
	"fmt"

	"github.com/mdlayher/wireguardctrl"
	"github.com/mdlayher/wireguardctrl/wgtypes"

	nl "github.com/vishvananda/netlink"
)

// GetDevice returns the WireGuard interface and the link device for an interface name
func GetDevice(ifname string) (*wgtypes.Device, nl.Link, error) {
	nlcl, err := wireguardctrl.New()
	if err != nil {
		return nil, nil, fmt.Errorf("could not create wireguard client: %s", err.Error())
	}

	dev, errwg := nlcl.Device(ifname)
	link, errrt := nl.LinkByName(ifname)
	if anyError(errwg, errrt) {
		return nil, nil, fmt.Errorf("could not find device: %s", firstError(errwg, errrt))
	}

	return dev, link, nil
}
