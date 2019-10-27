package wireguard

import (
	"fmt"

	"github.com/apognu/wgctl/lib"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	nl "github.com/vishvananda/netlink"
)

// GetDevice returns the WireGuard interface and the link device for an interface name
func GetDevice(ifname string) (*wgtypes.Device, nl.Link, error) {
	nlcl, err := wgctrl.New()
	if err != nil {
		return nil, nil, fmt.Errorf("could not create wireguard client: %s", err.Error())
	}

	dev, errwg := nlcl.Device(ifname)
	link, errrt := nl.LinkByName(ifname)
	if lib.AnyError(errwg, errrt) {
		return nil, nil, fmt.Errorf("could not find device: %s", lib.FirstError(errwg, errrt))
	}

	return dev, link, nil
}
