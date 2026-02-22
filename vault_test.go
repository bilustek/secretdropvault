package secretdropvault_test

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"
	"testing/iotest"

	"github.com/bilustek/secretdropvault"
)

func TestGenerateRandomKey(t *testing.T) {
	t.Parallel()

	key, err := secretdropvault.GenerateRandomKey()
	if err != nil {
		t.Fatalf("GenerateRandomKey() error = %v", err)
	}

	if len(key) != secretdropvault.KeySize {
		t.Errorf("key length = %d; want %d", len(key), secretdropvault.KeySize)
	}

	key2, err := secretdropvault.GenerateRandomKey()
	if err != nil {
		t.Fatalf("GenerateRandomKey() error = %v", err)
	}

	if string(key) == string(key2) {
		t.Error("two generated keys should not be equal")
	}
}

func TestGenerateRandomKeyRandFailure(t *testing.T) {
	original := rand.Reader
	rand.Reader = iotest.ErrReader(errors.New("entropy failure"))

	t.Cleanup(func() { rand.Reader = original })

	_, err := secretdropvault.GenerateRandomKey()
	if err == nil {
		t.Error("GenerateRandomKey() should fail when rand.Reader fails")
	}
}

func TestGenerateToken(t *testing.T) {
	t.Parallel()

	token, err := secretdropvault.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	if token == "" {
		t.Error("token should not be empty")
	}

	token2, err := secretdropvault.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	if token == token2 {
		t.Error("two generated tokens should not be equal")
	}
}

func TestGenerateTokenRandFailure(t *testing.T) {
	original := rand.Reader
	rand.Reader = iotest.ErrReader(errors.New("entropy failure"))

	t.Cleanup(func() { rand.Reader = original })

	_, err := secretdropvault.GenerateToken()
	if err == nil {
		t.Error("GenerateToken() should fail when rand.Reader fails")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	t.Parallel()

	key := make([]byte, secretdropvault.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	derived1, err := secretdropvault.DeriveKey(key, "test@example.com")
	if err != nil {
		t.Fatalf("DeriveKey() error = %v", err)
	}

	derived2, err := secretdropvault.DeriveKey(key, "test@example.com")
	if err != nil {
		t.Fatalf("DeriveKey() error = %v", err)
	}

	if string(derived1) != string(derived2) {
		t.Error("same inputs should produce same derived key")
	}
}

func TestDeriveKeyDifferentInfo(t *testing.T) {
	t.Parallel()

	key := make([]byte, secretdropvault.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	derived1, err := secretdropvault.DeriveKey(key, "alice@example.com")
	if err != nil {
		t.Fatalf("DeriveKey() error = %v", err)
	}

	derived2, err := secretdropvault.DeriveKey(key, "bob@example.com")
	if err != nil {
		t.Fatalf("DeriveKey() error = %v", err)
	}

	if string(derived1) == string(derived2) {
		t.Error("different info strings should produce different derived keys")
	}
}


func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	key := make([]byte, secretdropvault.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("RESEND_API_KEY=re_xxxxx")

	ciphertext, nonce, err := secretdropvault.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if string(ciphertext) == string(plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted, err := secretdropvault.Decrypt(key, ciphertext, nonce)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypt() = %q; want %q", decrypted, plaintext)
	}
}

func TestEncryptInvalidKeySize(t *testing.T) {
	t.Parallel()

	badKey := make([]byte, 15) // AES requires 16, 24, or 32

	_, _, err := secretdropvault.Encrypt(badKey, []byte("test"))
	if err == nil {
		t.Error("Encrypt() with invalid key size should fail")
	}
}

func TestEncryptRandFailure(t *testing.T) {
	original := rand.Reader
	rand.Reader = iotest.ErrReader(errors.New("entropy failure"))

	t.Cleanup(func() { rand.Reader = original })

	key := make([]byte, secretdropvault.KeySize)

	_, _, err := secretdropvault.Encrypt(key, []byte("test"))
	if err == nil {
		t.Error("Encrypt() should fail when rand.Reader fails")
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	t.Parallel()

	key := make([]byte, secretdropvault.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("secret data")

	ciphertext, nonce, err := secretdropvault.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	wrongKey := make([]byte, secretdropvault.KeySize)
	for i := range wrongKey {
		wrongKey[i] = byte(i + 1)
	}

	_, err = secretdropvault.Decrypt(wrongKey, ciphertext, nonce)
	if err == nil {
		t.Error("Decrypt() with wrong key should fail")
	}
}

func TestDecryptInvalidKeySize(t *testing.T) {
	t.Parallel()

	badKey := make([]byte, 15) // AES requires 16, 24, or 32

	_, err := secretdropvault.Decrypt(badKey, []byte("ciphertext"), []byte("nonce"))
	if err == nil {
		t.Error("Decrypt() with invalid key size should fail")
	}
}

func TestHashEmail(t *testing.T) {
	t.Parallel()

	hash1 := secretdropvault.HashEmail("test@example.com")
	hash2 := secretdropvault.HashEmail("test@example.com")
	hash3 := secretdropvault.HashEmail("other@example.com")

	if hash1 != hash2 {
		t.Error("same email should produce same hash")
	}

	if hash1 == hash3 {
		t.Error("different emails should produce different hashes")
	}

	if len(hash1) != 64 {
		t.Errorf("hash length = %d; want 64 (hex-encoded SHA-256)", len(hash1))
	}
}

func TestEncodeDecodeKeyRoundTrip(t *testing.T) {
	t.Parallel()

	original := make([]byte, secretdropvault.KeySize)
	for i := range original {
		original[i] = byte(i)
	}

	encoded := secretdropvault.EncodeKey(original)

	decoded, err := secretdropvault.DecodeKey(encoded)
	if err != nil {
		t.Fatalf("DecodeKey() error = %v", err)
	}

	if string(decoded) != string(original) {
		t.Error("round-trip encode/decode should preserve key")
	}
}

func TestDecodeKeyInvalidBase64(t *testing.T) {
	t.Parallel()

	_, err := secretdropvault.DecodeKey("!!!not-valid-base64!!!")
	if err == nil {
		t.Error("DecodeKey() with invalid base64 should fail")
	}
}

func TestFullCryptoFlow(t *testing.T) {
	t.Parallel()

	addr := "vigo@me.com"
	secretText := "DB_PASSWORD=super-secret-123"

	// 1. Generate a random key
	randomKey, err := secretdropvault.GenerateRandomKey()
	if err != nil {
		t.Fatalf("GenerateRandomKey() error = %v", err)
	}

	// 2. Derive an encryption key bound to the recipient
	finalKey, err := secretdropvault.DeriveKey(randomKey, addr)
	if err != nil {
		t.Fatalf("DeriveKey() error = %v", err)
	}

	// 3. Encrypt
	ciphertext, nonce, err := secretdropvault.Encrypt(finalKey, []byte(secretText))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// 4. Encode key for URL transport
	encoded := secretdropvault.EncodeKey(randomKey)

	// 5. Decode key (simulating the recipient)
	decodedKey, err := secretdropvault.DecodeKey(encoded)
	if err != nil {
		t.Fatalf("DecodeKey() error = %v", err)
	}

	// 6. Re-derive the encryption key
	recoveredKey, err := secretdropvault.DeriveKey(decodedKey, addr)
	if err != nil {
		t.Fatalf("DeriveKey() error = %v", err)
	}

	// 7. Decrypt
	decrypted, err := secretdropvault.Decrypt(recoveredKey, ciphertext, nonce)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if string(decrypted) != secretText {
		t.Errorf("full flow: got %q; want %q", decrypted, secretText)
	}

	// 8. Wrong recipient cannot decrypt
	wrongKey, err := secretdropvault.DeriveKey(decodedKey, "wrong@email.com")
	if err != nil {
		t.Fatalf("DeriveKey() error = %v", err)
	}

	_, err = secretdropvault.Decrypt(wrongKey, ciphertext, nonce)
	if err == nil {
		t.Error("decrypt with wrong recipient-derived key should fail")
	}
}

func TestEncryptGCMFailure(t *testing.T) {
	restore := secretdropvault.MockNewGCM(func(_ cipher.Block) (cipher.AEAD, error) {
		return nil, errors.New("gcm failure")
	})
	t.Cleanup(restore)

	key := make([]byte, secretdropvault.KeySize)

	_, _, err := secretdropvault.Encrypt(key, []byte("test"))
	if err == nil {
		t.Error("Encrypt() should fail when NewGCM fails")
	}
}

func TestDecryptGCMFailure(t *testing.T) {
	restore := secretdropvault.MockNewGCM(func(_ cipher.Block) (cipher.AEAD, error) {
		return nil, errors.New("gcm failure")
	})
	t.Cleanup(restore)

	key := make([]byte, secretdropvault.KeySize)

	_, err := secretdropvault.Decrypt(key, []byte("ciphertext"), []byte("nonce"))
	if err == nil {
		t.Error("Decrypt() should fail when NewGCM fails")
	}
}

func TestDeriveKeyHKDFFailure(t *testing.T) {
	restore := secretdropvault.MockHKDFKey(func(_, _ []byte, _ string, _ int) ([]byte, error) {
		return nil, errors.New("hkdf failure")
	})
	t.Cleanup(restore)

	key := make([]byte, secretdropvault.KeySize)

	_, err := secretdropvault.DeriveKey(key, "test@example.com")
	if err == nil {
		t.Error("DeriveKey() should fail when hkdfKey fails")
	}
}
