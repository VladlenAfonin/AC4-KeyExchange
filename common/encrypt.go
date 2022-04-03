package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	pkcs7 "github.com/mergermarket/go-pkcs7"
)

func Encrypt(pt, k []byte) ([]byte, error) {
	pt, err := pkcs7.Pad(pt, aes.BlockSize)

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	ct := make([]byte, aes.BlockSize+len(pt))

	iv := ct[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ct[aes.BlockSize:], pt)

	return ct, nil
}

func Decrypt(ct, k []byte) ([]byte, error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	iv := ct[:aes.BlockSize]

	// Don't want ct to change. Make pt copying it
	pt := make([]byte, len(ct)-aes.BlockSize)
	copy(pt, ct[aes.BlockSize:])

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(pt, pt)

	return pkcs7.Unpad(pt, aes.BlockSize)
}
