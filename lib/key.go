package lib

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/mdlayher/wireguardctrl/wgtypes"
	"golang.org/x/crypto/curve25519"
)

// EmptyPSK is the byte representation used when no preshared key is set on a peer
var EmptyPSK = [32]byte{
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
}

// GeneratePrivateKey generates a new Curve25519 private key from crypto/rand
func GeneratePrivateKey() (*PrivateKey, error) {
	priv := new([wgtypes.KeyLen]byte)
	_, err := io.ReadFull(rand.Reader, priv[:])
	if err != nil {
		return nil, fmt.Errorf("could not generate key: %s", err.Error())
	}

	return &PrivateKey{Data: *priv}, nil
}

// ComputePublicKey computes the matching Curve25519 public key from a private key
func ComputePublicKey(b []byte) Key {
	priv := new([wgtypes.KeyLen]byte)
	pub := new([wgtypes.KeyLen]byte)

	copy(priv[:], b)
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
