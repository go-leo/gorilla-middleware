package rsax

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSign(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyHex(1024)
	assert.NoError(t, err)

	rawData := []byte("he is hello kitty")
	signHex, err := SignHex(rawData, privateKey)
	assert.NoError(t, err)

	err = VerifySignHex(rawData, signHex, publicKey)
	assert.NoError(t, err)
}

func TestCrypt(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyHex(1024)
	assert.NoError(t, err)

	rawData := []byte("he is hello kitty")
	encryptDate, err := EncryptToHex(rawData, publicKey)
	assert.NoError(t, err)

	data, err := DecryptByHex(encryptDate, privateKey)
	assert.NoError(t, err)

	assert.Equal(t, rawData, data)
}
