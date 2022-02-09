package eccrsa

import (
	"testing"

	"github.com/regnull/easyecc"
	"github.com/stretchr/testify/assert"
)

func Test_DeriveKey(t *testing.T) {
	assert := assert.New(t)

	pk, err := easyecc.NewRandomPrivateKey()
	assert.NoError(err)

	rsaKey, err := DeriveKey(pk.ToECDSA(), 4096)
	assert.NoError(err)
	assert.NotNil(rsaKey)

	rsaKey1, err := DeriveKey(pk.ToECDSA(), 4096)
	assert.NoError(err)
	assert.True(rsaKey.Equal(rsaKey1))
}
