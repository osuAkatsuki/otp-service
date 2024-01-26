package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

func AesEncrypt(s, key string) (string, string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}

	output := make([]byte, len(s))
	cipherText := gcm.Seal(output, nonce, []byte(s), nil)

	return base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(cipherText), nil
}

func AesDecrypt(c, key, nonce string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return "", err
	}

	cipherBytes, err := base64.StdEncoding.DecodeString(c)
	if err != nil {
		return "", err
	}

	b, err := gcm.Open(nil, nonceBytes, cipherBytes, nil)
	if err != nil {
		return "", err
	}

	return string(b), nil
}
