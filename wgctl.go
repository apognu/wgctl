package main

import (
	"fmt"
	"os"

	"github.com/apognu/wgctl/wireguard"
	"github.com/sirupsen/logrus"

	nl "github.com/vishvananda/netlink"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	instanceDesc = "name or path to a WireGuard configuration"
)

var (
	buildVersion = "(dev)"
)

func main() {
	f, err := nl.GenlFamilyGet("wireguard")
	if err != nil {
		logrus.Fatalf("could not find WireGuard netlink family on your kernel, is the WireGuard module loaded?")
	}
	wireguard.NetlinkFamily = f.ID

	app := kingpin.New("wgctl", "WireGuard control plane helper")
	app.HelpFlag.Short('h')
	app.UsageTemplate(kingpin.CompactUsageTemplate)

	appStart := app.Command("start", "Bring up a tunnel.").Alias("up").PreAction(requireRoot)
	appStartInstance := appStart.Arg("instance", instanceDesc).Required().String()
	appStartNoRoutes := appStart.Flag("no-routes", "do not set up routing").Default("false").Bool()

	appStop := app.Command("stop", "Tear down a tunnel.").Alias("down").PreAction(requireRoot)
	appStopInstance := appStop.Arg("instance", instanceDesc).Required().String()

	appRestart := app.Command("restart", "Restart a tunnel from its configuration.").PreAction(requireRoot)
	appRestartInstance := appRestart.Arg("instance", instanceDesc).Required().String()
	appRestartNoRoutes := appRestart.Flag("no-routes", "do not set up routing").Default("false").Bool()

	appStatus := app.Command("status", "Show tunnel status.").PreAction(requireRoot)
	appStatusInstance := appStatus.Arg("instance", instanceDesc).String()
	appStatusShort := appStatus.Flag("short", "only display the names of active tunnels").Short('s').Default("false").Bool()

	appInfo := app.Command("info", "Get tunnel information.").PreAction(requireRoot)
	appInfoInstance := appInfo.Arg("instance", "name of your WireGuard configuration").Required().String()

	appKey := app.Command("key", "Manage WireGuard keys")
	appKeyGenerate := appKey.Command("generate", "generate a new private key")
	appKeyPublic := appKey.Command("public", "compute public key from a private key from stdin'")

	appVersion := app.Command("version", "Get version information.")

	args := kingpin.MustParse(app.Parse(os.Args[1:]))

	switch args {
	case appStart.FullCommand():
		start(*appStartInstance, *appStartNoRoutes)
	case appStop.FullCommand():
		stop(*appStopInstance)
	case appRestart.FullCommand():
		stop(*appRestartInstance)
		start(*appRestartInstance, *appRestartNoRoutes)
	case appStatus.FullCommand():
		status(*appStatusInstance, *appStatusShort, false)
	case appInfo.FullCommand():
		info(*appInfoInstance)
	case appVersion.FullCommand():
		version()
	case appKeyGenerate.FullCommand():
		generateKey()
	case appKeyPublic.FullCommand():
		generatePublicKey()
	}
}

func requireRoot(context *kingpin.ParseContext) error {
	if os.Getuid() > 0 {
		return fmt.Errorf("this command requires running as root")
	}
	return nil
}
