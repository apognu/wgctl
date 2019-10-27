package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/apognu/wgctl/lib"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/sirupsen/logrus"
)

func generateKey() {
	k, err := lib.GeneratePrivateKey()
	if err != nil {
		logrus.Fatalf("could not generate private key: %s", err.Error())
	}

	fmt.Println(k.String())
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

	k := lib.ComputePublicKey(b)

	fmt.Println(k.String())
}

func generatePSK() {
	k, err := lib.GeneratePSK()
	if err != nil {
		logrus.Fatalf("could not generate private key: %s", err.Error())
	}

	fmt.Println(k.String())
}
