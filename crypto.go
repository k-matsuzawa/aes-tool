package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/pkg/errors"
)

type Client interface {
	Decrypt(key []byte, value []byte) (decryptedTarget []byte, err error)
	DecryptFromBase64(key []byte, valueBase64 string) (decryptedTarget []byte, err error)
	DecryptToString(key []byte, valueBase64 string) (decrypted string, err error)
	DecryptWithIV(key []byte, value []byte, iv []byte) (decryptedTarget []byte, err error)
	DecryptWithIVFromBase64(key []byte, valueBase64 string, iv []byte) (decryptedTarget []byte, err error)
	DecryptWithIVToString(key []byte, valueBase64 string, iv []byte) (decrypted string, err error)

	Encrypt(key []byte, value []byte) (encryptedTarget []byte, err error)
	EncryptFromString(key []byte, valueStr string) (encryptedTarget []byte, err error)
	EncryptWithIV(key []byte, value []byte, iv []byte) (encryptedTarget []byte, err error)
	EncryptWithIVFromString(key []byte, valueStr string, iv []byte) (encryptedTarget []byte, err error)
}

type aesClient struct{}

func (a *aesClient) Decrypt(key []byte, value []byte) (decryptedTarget []byte, err error) {
	if len(value) < aes.BlockSize {
		return nil, errors.New("value too short.")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "create cipher.Block failed.")
	}
	decryptedText := make([]byte, len(value[aes.BlockSize:]))
	iv := value[:aes.BlockSize]
	decryptStream := cipher.NewCTR(block, iv)
	decryptStream.XORKeyStream(decryptedText, value[aes.BlockSize:])
	return decryptedText, nil
}

func (a *aesClient) DecryptFromBase64(key []byte, valueBase64 string) (decryptedTarget []byte, err error) {
	value, err := base64.StdEncoding.DecodeString(valueBase64)
	if err != nil {
		return nil, errors.Wrap(err, "base64 decode failed.")
	}
	data, err := a.Decrypt(key, value)
	if err != nil {
		return nil, errors.Wrap(err, "Decrypt failed.")
	}
	return data, nil
}

func (a *aesClient) DecryptToString(key []byte, valueBase64 string) (decrypted string, err error) {
	data, err := a.DecryptFromBase64(key, valueBase64)
	if err != nil {
		return "", errors.Wrap(err, "Decrypt failed.")
	}
	return string(data), nil
}

func (a *aesClient) DecryptWithIV(key []byte, value []byte, iv []byte) (decryptedTarget []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "create cipher.Block failed.")
	}
	decryptedText := make([]byte, len(value))
	decryptStream := cipher.NewCTR(block, iv)
	decryptStream.XORKeyStream(decryptedText, value)
	return decryptedText, nil
}

func (a *aesClient) DecryptWithIVFromBase64(key []byte, valueBase64 string, iv []byte) (decryptedTarget []byte, err error) {
	value, err := base64.StdEncoding.DecodeString(valueBase64)
	if err != nil {
		return nil, errors.Wrap(err, "base64 decode failed.")
	}
	data, err := a.DecryptWithIV(key, value, iv)
	if err != nil {
		return nil, errors.Wrap(err, "Decrypt failed.")
	}
	return data, nil
}

func (a *aesClient) DecryptWithIVToString(key []byte, valueBase64 string, iv []byte) (decrypted string, err error) {
	data, err := a.DecryptWithIVFromBase64(key, valueBase64, iv)
	if err != nil {
		return "", errors.Wrap(err, "Decrypt failed.")
	}
	return string(data), nil
}

func (a *aesClient) Encrypt(key []byte, value []byte) (encryptedTarget []byte, err error) {
	// Create new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "create cipher.Block failed.")
	}

	// Create IV
	cipherText := make([]byte, aes.BlockSize+len(value))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, errors.Wrap(err, "failed to read IV.")
	}

	// Encrypt
	encryptStream := cipher.NewCTR(block, iv)
	encryptStream.XORKeyStream(cipherText[aes.BlockSize:], value)
	return cipherText, nil
}

func (a *aesClient) EncryptFromString(key []byte, valueStr string) (encryptedTarget []byte, err error) {
	return a.Encrypt(key, []byte(valueStr))
}

func (a *aesClient) EncryptWithIV(key []byte, value []byte, iv []byte) (encryptedTarget []byte, err error) {
	// Create new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "create cipher.Block failed.")
	}

	// Use provided IV
	cipherText := make([]byte, len(value))

	// Encrypt
	encryptStream := cipher.NewCTR(block, iv)
	encryptStream.XORKeyStream(cipherText, value)
	return cipherText, nil
}

func (a *aesClient) EncryptWithIVFromString(key []byte, valueStr string, iv []byte) (encryptedTarget []byte, err error) {
	return a.EncryptWithIV(key, []byte(valueStr), iv)
}

func NewClient() *aesClient {
	return &aesClient{}
}
