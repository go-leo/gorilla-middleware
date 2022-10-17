package rsax

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"

	"github.com/wumansgy/goEncrypt/hash"
)

func SignHex(data []byte, priKey string) (string, error) {
	priBytes, err := hex.DecodeString(priKey)
	if err != nil {
		return "", err
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(priBytes)
	if err != nil {
		return "", err
	}
	hashed := hash.Sha256(data)
	sign, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sign), nil
}

func VerifySignHex(data []byte, hexSign, hexPubKey string) error {
	signBytes, err := hex.DecodeString(hexSign)
	if err != nil {
		return err
	}
	pubBytes, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return err
	}
	publicKey, err := x509.ParsePKCS1PublicKey(pubBytes)
	if err != nil {
		return err
	}
	hashed := hash.Sha256(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, signBytes)
}

func SignBase64(data []byte, priKey string) (string, error) {
	priBytes, err := base64.StdEncoding.DecodeString(priKey)
	if err != nil {
		return "", err
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(priBytes)
	if err != nil {
		return "", err
	}
	hashed := hash.Sha256(data)
	sign, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sign), nil
}

func VerifySignBase64(data []byte, base64Sign, base64PubKey string) error {
	signBytes, err := base64.StdEncoding.DecodeString(base64Sign)
	if err != nil {
		return err
	}
	pubBytes, err := base64.StdEncoding.DecodeString(base64PubKey)
	if err != nil {
		return err
	}
	publicKey, err := x509.ParsePKCS1PublicKey(pubBytes)
	if err != nil {
		return err
	}
	hashed := hash.Sha256(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, signBytes)
}
