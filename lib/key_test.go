package lib

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"github.com/stretchr/testify/assert"
)

func Test_GeneratePrivateKey(t *testing.T) {
	r := rand.Reader

	k, err := GeneratePrivateKey()
	assert.Nil(t, err)

	assert.Nil(t, err)
	assert.Equal(t, wgtypes.KeyLen, len(k.Data))
	assert.NotEmpty(t, EmptyPSK, k)

	rand.Reader = bytes.NewReader([]byte{})
	_, err = GeneratePrivateKey()
	assert.NotNil(t, err)

	rand.Reader = r
}

func Test_ComputePublicKey(t *testing.T) {
	priv, _ := GeneratePrivateKey()
	k1 := ComputePublicKey(priv.Data[:])
	k2 := ComputePublicKey(priv.Data[:])

	assert.Equal(t, wgtypes.KeyLen, len(k1))
	// Public key from empty private key
	assert.False(t, bytes.Equal([]byte{47, 229, 125, 163, 71, 205, 98, 67, 21, 40, 218, 172, 95, 187, 41, 7, 48, 255, 246, 132, 175, 196, 207, 194, 237, 144, 153, 95, 88, 203, 59, 116}, k1[:]))
	assert.Equal(t, k1, k2)
}

func Test_GeneratePSK(t *testing.T) {
	r := rand.Reader

	k, err := GeneratePSK()
	assert.Nil(t, err)

	assert.Nil(t, err)
	assert.Equal(t, wgtypes.KeyLen, len(k))
	assert.NotEmpty(t, EmptyPSK, k)

	rand.Reader = bytes.NewReader([]byte{})
	_, err = GeneratePSK()
	assert.NotNil(t, err)

	rand.Reader = r
}
