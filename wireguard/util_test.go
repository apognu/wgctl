package wireguard

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_FirstError(t *testing.T) {
	err1 := fmt.Errorf("error 1")
	err2 := fmt.Errorf("error 2")

	assert.Equal(t, err1, firstError(nil, err1, err2))
	assert.Equal(t, err2, firstError(nil, nil, nil, err2))
	assert.Nil(t, firstError(nil, nil))
}

func Test_AnyError(t *testing.T) {
	err1 := fmt.Errorf("error 1")
	err2 := fmt.Errorf("error 2")

	assert.True(t, anyError(nil, nil, err1))
	assert.True(t, anyError(err2, nil, err1))
	assert.False(t, anyError(nil, nil, nil))
}
