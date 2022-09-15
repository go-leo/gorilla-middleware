package cryptox

import (
	"crypto/md5"
	"encoding/hex"
)

func MD5(data []byte) []byte {
	hash := md5.New()
	hash.Write(data)
	return hash.Sum(nil)
}

func MD5HexString(data []byte) string {
	return hex.EncodeToString(MD5(data))
}
