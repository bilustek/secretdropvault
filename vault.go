// Package secretdropvault provides AES-256-GCM encryption with HKDF-SHA256 key
// derivation. It is the cryptographic engine behind SecretDrop — a one-time
// secret sharing service.
//
// Security model:
//   - A random 256-bit key is generated per secret.
//   - HKDF-SHA256 derives a unique encryption key per recipient (bound to their email).
//   - AES-256-GCM provides authenticated encryption with a random nonce.
//   - The random key is carried only in the URL fragment (never sent to the server).
//   - Email addresses are stored as SHA-256 hashes (never in plaintext).
package secretdropvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

const (
	// KeySize is the AES-256 key size in bytes.
	KeySize = 32

	// TokenSize is the number of random bytes used to generate a token.
	TokenSize = 16
)

// GenerateRandomKey creates a cryptographically secure random key of [KeySize] bytes.
func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate random key: %w", err)
	}

	return key, nil
}

// GenerateToken creates a random token encoded as base64url (no padding).
// The token is [TokenSize] random bytes, base64url-encoded.
func GenerateToken() (string, error) {
	b := make([]byte, TokenSize)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DeriveKey uses HKDF-SHA256 to derive a [KeySize]-byte key from the input key
// material and an info string (typically the recipient's email address).
func DeriveKey(randomKey []byte, info string) ([]byte, error) {
	derived, err := hkdf.Key(sha256.New, randomKey, nil, info, KeySize)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	return derived, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with the given key.
// Returns ciphertext (with appended authentication tag) and nonce.
func Encrypt(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)

	return ciphertext, nonce, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM with the given key and nonce.
func Decrypt(key, ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// HashEmail returns the hex-encoded SHA-256 hash of an email address.
func HashEmail(email string) string {
	h := sha256.Sum256([]byte(email))

	return hex.EncodeToString(h[:])
}

// EncodeKey encodes a key as base64url (no padding) for URL fragment usage.
func EncodeKey(key []byte) string {
	return base64.RawURLEncoding.EncodeToString(key)
}

// DecodeKey decodes a base64url-encoded key (no padding).
func DecodeKey(encoded string) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}

	return key, nil
}
