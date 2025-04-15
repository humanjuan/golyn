package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const keyPhrase = "<key_phrase_>"
const secretKey = "<secret_key_>"

func EncryptPassword(password string) (string, error) {
	key := []byte(secretKey)
	encryptedPhrase, err := encryptAESGCM([]byte(keyPhrase), key)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt key phrase: %v", err)
	}

	data := append(encryptedPhrase, []byte(password)...)

	finalCiphertext, err := encryptAESGCM(data, key)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt final data: %v", err)
	}

	encoded := base64.StdEncoding.EncodeToString(finalCiphertext)
	return fmt.Sprintf("ENC:AES256:%s", encoded), nil
}

func DecryptPassword(encrypted string) (string, error) {
	if !strings.HasPrefix(encrypted, "ENC:AES256:") {
		return "", errors.New("invalid encrypted format: missing ENC:AES256 prefix")
	}

	key := []byte(secretKey)
	encoded := strings.TrimPrefix(encrypted, "ENC:AES256:")
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %v", err)
	}

	data, err := decryptAESGCM(ciphertext, key)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data: %v", err)
	}
	// 28 bytes = (nonce + tag)
	for i := 28; i < len(data); i++ {
		possiblePhrase, err := decryptAESGCM(data[:i], key)
		if err == nil && string(possiblePhrase) == keyPhrase {
			return string(data[i:]), nil
		}
	}
	return "", errors.New("invalid key phrase: data tampered or wrong key")
}

func encryptAESGCM(data, key []byte) ([]byte, error) {
	// encrypts data using AES-GCM.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decryptAESGCM(ciphertext, key []byte) ([]byte, error) {
	// decrypts data encrypted with AES-GCM.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
