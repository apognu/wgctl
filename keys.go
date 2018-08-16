package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/apognu/wgctl/wireguard"
	"github.com/mdlayher/wireguardctrl/wgtypes"

	"github.com/sirupsen/logrus"
)

func generateKey() {
	fmt.Println(wireguard.GeneratePrivateKey())
}

func generatePublicKey() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()

	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(scanner.Text()))
	if err != nil {
		logrus.Fatalf("could not read private key from stdin: %s", err.Error())
	}
	if len(b) != wgtypes.KeyLen {
		logrus.Fatalf("the key read from stdin is of an invalid size")
	}

	fmt.Println(wireguard.ComputePublicKey(b))
}

func generatePSK() {
	fmt.Println(wireguard.GeneratePSK())
}
