package main

import (
	"fmt"
	"os"

	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	instanceDesc = "name or path to a WireGuard configuration"
)

var (
	buildVersion = "(dev)"
)

func main() {
	kp := kingpin.New("wgctl", "WireGuard control plane helper")
	kp.HelpFlag.Short('h')
	kp.UsageTemplate(kingpin.CompactUsageTemplate)

	kpStart := kp.Command("start", "Bring up a tunnel.").Alias("up").PreAction(requireRoot)
	kpStartInstance := kpStart.Arg("instance", instanceDesc).Required().String()
	kpStartNoRoutes := kpStart.Flag("no-routes", "do not set up routing").Default("false").Bool()

	kpStop := kp.Command("stop", "Tear down a tunnel.").Alias("down").PreAction(requireRoot)
	kpStopInstance := kpStop.Arg("instance", instanceDesc).Required().String()

	kpRestart := kp.Command("restart", "Restart a tunnel from its configuration.").PreAction(requireRoot)
	kpRestartInstance := kpRestart.Arg("instance", instanceDesc).Required().String()
	kpRestartNoRoutes := kpRestart.Flag("no-routes", "do not set up routing").Default("false").Bool()

	kpStatus := kp.Command("status", "Show tunnel status.").PreAction(requireRoot)
	kpStatusInstance := kpStatus.Arg("instance", instanceDesc).String()
	kpStatusShort := kpStatus.Flag("short", "only display the names of active tunnels").Short('s').Default("false").Bool()

	kpInfo := kp.Command("info", "Get tunnel information.").PreAction(requireRoot)
	kpInfoInstance := kpInfo.Arg("instance", "name of your WireGuard configuration").Required().String()

	kpSet := kp.Command("set", "Set live tunnel properties").PreAction(requireRoot)
	kpSetInstance := kpSet.Arg("instance", "name of your WireGuard configuration").Required().String()
	kpSetParameters := kpSet.Arg("settings", "list of key=value to apply to the wireguard interface").StringMap()

	kpPeer := kp.Command("peer", "Set live tunnel peers")

	kpPeerSet := kpPeer.Command("set", "add a new peer to a live tunnel").PreAction(requireRoot)
	kpPeerSetInstance := kpPeerSet.Arg("instance", "name of your WireGuard configuration").Required().String()
	kpPeerSetPeer := kpPeerSet.Arg("peer", "list of key=value to the new peer").Required().StringMap()

	kpPeerReplace := kpPeer.Command("replace", "replace all peers on a live tunnel").PreAction(requireRoot)
	kpPeerReplaceInstance := kpPeerReplace.Arg("instance", "name of your WireGuard configuration").Required().String()
	kpPeerReplacePeer := kpPeerReplace.Arg("peer", "list of key=value to the new peer").Required().StringMap()

	kpExport := kp.Command("export", "export the configuration of an active tunnel to YAML").PreAction(requireRoot)
	kpExportInstance := kpExport.Arg("instance", "name of your WireGuard configuration").Required().String()

	kpKey := kp.Command("key", "Manage WireGuard keys")
	kpKeyGenerate := kpKey.Command("private", "generate a new private key")
	kpKeyPublic := kpKey.Command("public", "compute public key from a private key from stdin")
	kpKeyPSK := kpKey.Command("psk", "generate a preshared key to be used to authenticate an endpoint")

	kpVersion := kp.Command("version", "Get version information.")

	args := kingpin.MustParse(kp.Parse(os.Args[1:]))

	switch args {
	case kpStart.FullCommand():
		start(*kpStartInstance, *kpStartNoRoutes)
	case kpStop.FullCommand():
		stop(*kpStopInstance)
	case kpRestart.FullCommand():
		stop(*kpRestartInstance)
		start(*kpRestartInstance, *kpRestartNoRoutes)
	case kpStatus.FullCommand():
		status(*kpStatusInstance, *kpStatusShort, false)
	case kpInfo.FullCommand():
		info(*kpInfoInstance)
	case kpSet.FullCommand():
		set(*kpSetInstance, *kpSetParameters)
	case kpPeerSet.FullCommand():
		setPeers(*kpPeerSetInstance, *kpPeerSetPeer, false)
	case kpPeerReplace.FullCommand():
		setPeers(*kpPeerReplaceInstance, *kpPeerReplacePeer, true)
	case kpVersion.FullCommand():
		version()
	case kpExport.FullCommand():
		exportConfig(*kpExportInstance)
	case kpKeyGenerate.FullCommand():
		generateKey()
	case kpKeyPublic.FullCommand():
		generatePublicKey()
	case kpKeyPSK.FullCommand():
		generatePSK()
	}
}

func requireRoot(context *kingpin.ParseContext) error {
	if os.Getuid() > 0 {
		return fmt.Errorf("this command requires running as root")
	}
	return nil
}
