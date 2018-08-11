package main

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/apognu/wgctl/wireguard"
)

func start(instance string, noRoutes bool) {
	config := wireguard.ParseConfig(instance)
	instance = wireguard.GetInstanceFromArg(instance)

	wireguard.AddDevice(instance, config)
	wireguard.ConfigureDevice(instance, config)
	if !noRoutes && *config.Interface.SetUpRoutes {
		wireguard.AddDeviceRoutes(instance, config)
	}

	Up("tunnel '%s' has been brought up", instance)

	if len(config.Interface.PostUp) > 0 {
		for _, cmdSpec := range config.Interface.PostUp {
			execute(cmdSpec)
		}
	}
}

func stop(instance string) {
	config := wireguard.ParseConfig(instance)
	instance = wireguard.GetInstanceFromArg(instance)

	wireguard.DeleteDevice(instance)

	if len(config.Interface.PreDown) > 0 {
		for _, cmdSpec := range config.Interface.PreDown {
			execute(cmdSpec)
		}
	}

	Down("tunnel '%s' has been torn down", instance)
}

func execute(cmdSpec []string) {
	if len(cmdSpec) == 0 {
		return
	}

	if !strings.HasPrefix(cmdSpec[0], "/") {
		logrus.Warn("ignoring lifecycle hook not using an absolute path")
		return
	}

	var cmd *exec.Cmd
	stderr := new(bytes.Buffer)
	if len(cmdSpec) == 1 {
		cmd = exec.Command(cmdSpec[0])
	} else {
		cmd = exec.Command(cmdSpec[0], cmdSpec[1:]...)
	}

	cmd.Stderr = stderr

	err := cmd.Run()
	if err != nil {
		logrus.Warnf("lifecycle hook returned an error: %s", err.Error())
	}
}
