package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/apognu/wgctl/wireguard"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/curve25519"
)

func generateKey() {
	priv := new([wireguard.KeyLength]byte)
	_, err := io.ReadFull(rand.Reader, priv[:])
	if err != nil {
		logrus.Fatalf("could not generate key: %s", err.Error())
	}

	fmt.Println(base64.StdEncoding.EncodeToString(priv[:]))
}

func generatePublicKey() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()

	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(scanner.Text()))
	if err != nil {
		logrus.Fatalf("could not read private key from stdin: %s", err.Error())
	}
	if len(b) != wireguard.KeyLength {
		logrus.Fatalf("the key read from stdin is of an invalid size")
	}

	priv := new([wireguard.KeyLength]byte)
	pub := new([wireguard.KeyLength]byte)
	for idx, b := range b {
		priv[idx] = b
	}

	curve25519.ScalarBaseMult(pub, priv)

	fmt.Println(base64.StdEncoding.EncodeToString(pub[:]))
}
