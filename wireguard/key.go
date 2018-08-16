package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/mdlayher/wireguardctrl/wgtypes"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/curve25519"
)

// GeneratePrivateKey generates a new Curve25519 private key from crypto/rand
func GeneratePrivateKey() string {
	priv := new([wgtypes.KeyLen]byte)
	_, err := io.ReadFull(rand.Reader, priv[:])
	if err != nil {
		logrus.Fatalf("could not generate key: %s", err.Error())
	}

	return base64.StdEncoding.EncodeToString(priv[:])
}

// ComputePublicKey computes the matching Curve25519 public key from a private key
func ComputePublicKey(b []byte) string {
	priv := new([wgtypes.KeyLen]byte)
	pub := new([wgtypes.KeyLen]byte)
	for idx, b := range b {
		priv[idx] = b
	}

	curve25519.ScalarBaseMult(pub, priv)

	return base64.StdEncoding.EncodeToString(pub[:])
}

// GeneratePSK generates a random preshared key to be used with a WireGuard peer
func GeneratePSK() string {
	priv := new([wgtypes.KeyLen]byte)
	_, err := io.ReadFull(rand.Reader, priv[:])
	if err != nil {
		logrus.Fatalf("could not generate key: %s", err.Error())
	}

	return fmt.Sprintf("%x", priv[:])
}
