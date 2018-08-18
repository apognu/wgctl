package lib

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type randReader struct{}

func (randReader) Read(b []byte) (int, error) {
	copy(b, []byte{42})

	return 1, nil
}

func Test_GetEndpoint(t *testing.T) {
	rand.Seed(0)

	ep := GetEndpoint(t)

	assert.Equal(t, []byte{159, 144, 163, 226}, []byte(ep.IP))
	assert.Equal(t, 27515, ep.Port)

	rand.Seed(time.Now().Unix())
}

func Test_GetSubnet(t *testing.T) {
	rand.Seed(0)

	ep := GetSubnet(t)

	assert.Equal(t, []byte{159, 144, 163, 224}, []byte(ep.IP))
	assert.Equal(t, []byte{255, 255, 255, 224}, []byte(ep.Mask))

	rand.Seed(time.Now().Unix())
}
