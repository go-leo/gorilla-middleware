package rsax

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
)

func GenerateKey(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, err
}

func GenerateKeyPKCS1(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, err error) ([]byte, []byte, error) {
	if err != nil {
		return nil, nil, err
	}
	return x509.MarshalPKCS1PrivateKey(privateKey), x509.MarshalPKCS1PublicKey(publicKey), err
}

func GenerateRsaKeyHex(privateKey []byte, publicKey []byte, err error) (string, string, error) {
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(privateKey), hex.EncodeToString(publicKey), nil
}

func GenerateRsaKeyBase64(privateKey []byte, publicKey []byte, err error) (string, string, error) {
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(privateKey), base64.StdEncoding.EncodeToString(publicKey), nil
}
