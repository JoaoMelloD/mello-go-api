package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

type SecretCipher struct {
	aead cipher.AEAD
}

func NewSecretCipher(key []byte) (*SecretCipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("chave de criptografia deve ter 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &SecretCipher{aead: aead}, nil
}

func (c *SecretCipher) EncryptString(plaintext string) (string, string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", "", err
	}

	ciphertext := c.aead.Seal(nil, nonce, []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(ciphertext), base64.StdEncoding.EncodeToString(nonce), nil
}

func (c *SecretCipher) DecryptString(ciphertextText string, nonceText string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextText)
	if err != nil {
		return "", err
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceText)
	if err != nil {
		return "", err
	}

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
