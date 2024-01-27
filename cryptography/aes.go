package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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

	cipherText := gcm.Seal(nil, nonce, []byte(s), nil)

	return fmt.Sprintf("%x", nonce), fmt.Sprintf("%x", cipherText), nil
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

	nonceBytes, err := hex.DecodeString(nonce)
	if err != nil {
		return "", err
	}

	cipherBytes, err := hex.DecodeString(c)
	if err != nil {
		return "", err
	}

	b, err := gcm.Open(nil, nonceBytes, cipherBytes, nil)
	if err != nil {
		return "", err
	}

	return string(b), nil
}
