package lib

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_FirstError(t *testing.T) {
	err1 := fmt.Errorf("error 1")
	err2 := fmt.Errorf("error 2")

	assert.Equal(t, err1, FirstError(nil, err1, err2))
	assert.Equal(t, err2, FirstError(nil, nil, nil, err2))
	assert.Nil(t, FirstError(nil, nil))
}

func Test_AnyError(t *testing.T) {
	err1 := fmt.Errorf("error 1")
	err2 := fmt.Errorf("error 2")

	assert.True(t, AnyError(nil, nil, err1))
	assert.True(t, AnyError(err2, nil, err1))
	assert.False(t, AnyError(nil, nil, nil))
}
