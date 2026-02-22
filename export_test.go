package secretdropvault

import "crypto/cipher"

// MockNewGCM replaces the internal newGCM function for testing.
// Returns a restore function that must be called to reset the original.
func MockNewGCM(f func(cipher.Block) (cipher.AEAD, error)) func() {
	old := newGCM
	newGCM = f

	return func() { newGCM = old }
}

// MockHKDFKey replaces the internal hkdfKey function for testing.
// Returns a restore function that must be called to reset the original.
func MockHKDFKey(f func(secret, salt []byte, info string, length int) ([]byte, error)) func() {
	old := hkdfKey
	hkdfKey = f

	return func() { hkdfKey = old }
}
