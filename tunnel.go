package main

import (
	"github.com/apognu/wgctl/wireguard"
)

func start(instance string, routes bool) {
	config := wireguard.ParseConfig(instance)
	instance = wireguard.GetInstanceFromArg(instance)

	wireguard.AddDevice(instance, config)
	wireguard.ConfigureDevice(instance, config)
	if routes {
		wireguard.AddDeviceRoutes(instance, config)
	}
}

func stop(instance string) {
	instance = wireguard.GetInstanceFromArg(instance)

	wireguard.DeleteDevice(instance)
}
