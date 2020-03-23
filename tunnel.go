package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/apognu/wgctl/lib"
	"github.com/apognu/wgctl/wireguard"
)

func start(instance string, noRoutes, foreground bool) {
	config, err := lib.ParseConfig(instance)
	if err != nil {
		logrus.Fatal(err)
	}
	instance = lib.GetInstanceFromArg(instance)

	err = wireguard.AddDevice(instance, config)
	if err != nil {
		logrus.Fatal(err)
	}
	err = wireguard.ConfigureDevice(instance, config, true)
	if err != nil {
		logrus.Fatal(err)
	}
	if !noRoutes && *config.Interface.SetUpRoutes {
		err = wireguard.AddDeviceRoutes(instance, config)
		if err != nil {
			logrus.Fatal(err)
		}
	}

	Up("tunnel '%s' has been brought up", instance)

	if len(config.Interface.PostUp) > 0 {
		for _, cmdSpec := range config.Interface.PostUp {
			execute(cmdSpec)
		}
	}

	if foreground {
		sg := make(chan os.Signal)
		signal.Notify(sg, os.Interrupt, syscall.SIGTERM)

		<-sg

		stop(instance)
	}
}

func stop(instance string) {
	config, err := lib.ParseConfig(instance)
	if err != nil {
		logrus.Fatal(err)
	}
	instance = lib.GetInstanceFromArg(instance)

	wireguard.DeleteDevice(instance)

	if len(config.Interface.PreDown) > 0 {
		for _, cmdSpec := range config.Interface.PreDown {
			execute(cmdSpec)
		}
	}

	Down("tunnel '%s' has been torn down", instance)
}

func set(instance string, props map[string]string) {
	c := wgtypes.Config{}
	for k, v := range props {
		switch k {
		case "port":
			port, err := strconv.Atoi(v)
			if err != nil {
				logrus.Fatalf("could not parse port '%s': %s", v, err.Error())
			}
			c.ListenPort = &port
		case "fwmark":
			mark, err := strconv.Atoi(v)
			if err != nil {
				logrus.Fatalf("could not parse fwmark '%s': %s", v, err.Error())
			}
			c.FirewallMark = &mark
		case "privkey":
			k := new(lib.PrivateKey)
			err := k.UnmarshalYAML(func(s interface{}) error {
				*s.(*string) = "/etc/wireguard/gcp.key"
				return nil
			})
			if err != nil {
				logrus.Fatal(err)
			}

			key := wgtypes.Key(k.Bytes())

			c.PrivateKey = &key
		}
	}

	err := wireguard.SetDevice(instance, c, false)
	if err != nil {
		logrus.Fatal(err)
	}
}

func setPeers(instance string, props map[string]string, replace bool) {
	p := wgtypes.PeerConfig{}
	for k, v := range props {
		switch k {
		case "pubkey":
			bk, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				logrus.Fatalf("could not decode public key: %s", err.Error())
			}
			k := []byte(bk)

			p.PublicKey, _ = wgtypes.NewKey(k)
		case "psk":
			bk, err := hex.DecodeString(v)
			if err != nil {
				logrus.Fatalf("could not decode preshared key: %s", err.Error())
			}
			k, err := wgtypes.NewKey(bk)
			if err != nil {
				logrus.Fatalf("could not decode preshared key: %s", err.Error())
			}

			p.PresharedKey = &k
		case "endpoint":
			addr, err := net.ResolveUDPAddr("udp", v)
			if err != nil {
				logrus.Fatalf("could not parse UDP address '%s': %s", v, err.Error())
			}

			p.Endpoint = addr
		case "allowedips":
			strs := strings.Split(v, ",")
			ips := make([]net.IPNet, len(strs))
			for idx, ip := range strs {
				_, sub, err := net.ParseCIDR(ip)
				if err != nil {
					logrus.Fatalf("could not parse allowed IP '%s': %s", ip, err.Error())
				}
				ips[idx] = *sub
			}

			p.AllowedIPs = ips
		case "keepalive":
			ka, err := strconv.Atoi(v)
			if err != nil {
				logrus.Fatalf("could not parse keepalive interval '%s': %s", v, err.Error())
			}
			dur := time.Duration(ka) * time.Second

			p.PersistentKeepaliveInterval = &dur
		}
	}

	c := wgtypes.Config{Peers: []wgtypes.PeerConfig{p}}

	wireguard.SetDevice(instance, c, replace)
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
