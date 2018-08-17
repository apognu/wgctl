package wireguard

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/mdlayher/wireguardctrl/wgtypes"
	"github.com/stretchr/testify/assert"
)

func Test_GeneratePrivateKey(t *testing.T) {
	r := rand.Reader

	k, err := GeneratePrivateKey()
	assert.Nil(t, err)

	assert.Nil(t, err)
	assert.Equal(t, wgtypes.KeyLen, len(k))
	assert.NotEmpty(t, EmptyPSK, k)

	rand.Reader = bytes.NewReader([]byte{})
	_, err = GeneratePrivateKey()
	assert.NotNil(t, err)

	rand.Reader = r
}

func Test_ComputePublicKey(t *testing.T) {
	priv, _ := GeneratePrivateKey()
	k := ComputePublicKey(priv)

	assert.Equal(t, wgtypes.KeyLen, len(k))
	assert.NotEqual(t, EmptyPSK, k)
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
