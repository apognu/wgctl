package wireguard

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/mdlayher/wireguardctrl/wgtypes"
	"golang.org/x/crypto/curve25519"
)

// GeneratePrivateKey generates a new Curve25519 private key from crypto/rand
func GeneratePrivateKey() (Key, error) {
	priv := new([wgtypes.KeyLen]byte)
	_, err := io.ReadFull(rand.Reader, priv[:])
	if err != nil {
		return Key{}, fmt.Errorf("could not generate key: %s", err.Error())
	}

	return Key(priv[:]), nil
}

// ComputePublicKey computes the matching Curve25519 public key from a private key
func ComputePublicKey(b []byte) Key {
	priv := new([wgtypes.KeyLen]byte)
	pub := new([wgtypes.KeyLen]byte)
	for idx, b := range b {
		priv[idx] = b
	}

	curve25519.ScalarBaseMult(pub, priv)

	return Key(pub[:])
}

// GeneratePSK generates a random preshared key to be used with a WireGuard peer
func GeneratePSK() (PresharedKey, error) {
	priv := new([wgtypes.KeyLen]byte)
	_, err := io.ReadFull(rand.Reader, priv[:])
	if err != nil {
		return PresharedKey(EmptyPSK[:]), fmt.Errorf("could not generate key: %s", err.Error())
	}

	return PresharedKey(priv[:]), nil
}
