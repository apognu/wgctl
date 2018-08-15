package wireguard

import (
	"github.com/mdlayher/wireguardctrl"
	"github.com/mdlayher/wireguardctrl/wgtypes"
	"github.com/sirupsen/logrus"
)

func GetDevice(ifname string) (*wgtypes.Device, error) {
	nlcl, err := wireguardctrl.New()
	if err != nil {
		logrus.Fatalf("could not create wireguard client: %s", err.Error())
	}
	dev, err := nlcl.Device("gcp")
	if err != nil {
		logrus.Fatalf("could not find device: %s", err.Error())
	}

	return dev, nil
}
