package md5x

import (
	"crypto/md5"
	"encoding/hex"
)

func Hex(data []byte) string {
	return hex.EncodeToString(MD5(data))
}

func MD5(data []byte) []byte {
	digest := md5.New()
	digest.Write(data)
	return digest.Sum(nil)
}
