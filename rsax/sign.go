package rsax

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/wumansgy/goEncrypt/hash"
)

func SignHex(data []byte, priKey string) (string, error) {
	priBytes, err := hex.DecodeString(priKey)
	if err != nil {
		return "", err
	}
	sign, err := rsaSign(data, priBytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sign), nil
}

func VerifySignHex(data []byte, hexSign, hexPubKey string) bool {
	signBytes, err := hex.DecodeString(hexSign)
	if err != nil {
		return false
	}
	pubBytes, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return false
	}
	return verifySign(data, signBytes, pubBytes)
}

func SignBase64(data []byte, priKey string) (base64Sign string, err error) {
	priBytes, err := base64.StdEncoding.DecodeString(priKey)
	if err != nil {
		return "", err
	}
	sign, err := rsaSign(data, priBytes)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sign), nil
}

func VerifySignBase64(data []byte, base64Sign, base64PubKey string) bool {
	signBytes, err := base64.StdEncoding.DecodeString(base64Sign)
	if err != nil {
		return false
	}
	pubBytes, err := base64.StdEncoding.DecodeString(base64PubKey)
	if err != nil {
		return false
	}
	return verifySign(data, signBytes, pubBytes)
}

func rsaSign(data, priKey []byte) (signature []byte, err error) {
	defer func() {
		if p := recover(); p != nil {
			switch e := p.(type) {
			case error:
				err = e
			default:
				err = fmt.Errorf("panic triggered, %v", p)
			}
		}
	}()
	privateKey, err := x509.ParsePKCS1PrivateKey(priKey)
	hashed := hash.Sha256(data)
	signature, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func verifySign(data []byte, sign []byte, pubKey []byte) (verified bool) {
	defer func() {
		if p := recover(); p != nil {
			verified = false
		}
	}()
	publicKey, err := x509.ParsePKCS1PublicKey(pubKey)
	if err != nil {
		verified = false
		return
	}
	hashed := hash.Sha256(data)
	verified = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, sign) == nil
	return
}
