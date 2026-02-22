![Version](https://img.shields.io/badge/version-0.0.0-orange.svg)
![Go](https://img.shields.io/badge/go-1.26-00ADD8.svg?logo=go&logoColor=white)
[![codecov](https://codecov.io/github/bilustek/secretdropvault/graph/badge.svg?token=VDDN0QQ25M)](https://codecov.io/github/bilustek/secretdropvault)
[![Go Reference](https://pkg.go.dev/badge/github.com/bilustek/secretdropvault.svg)](https://pkg.go.dev/github.com/bilustek/secretdropvault)
[![Go Report Card](https://goreportcard.com/badge/github.com/bilustek/secretdropvault)](https://goreportcard.com/report/github.com/bilustek/secretdropvault)


# secretdropvault

AES-256-GCM encryption with HKDF-SHA256 key derivation — the crypto engine
behind [SecretDrop](https://secretdrop.us).

Zero dependencies beyond the Go standard library.

---

## Security Model

1. A **random 256-bit key** is generated per secret
2. **HKDF-SHA256** derives a unique encryption key per recipient (bound to their
   email address as the `info` parameter)
3. **AES-256-GCM** provides authenticated encryption with a random nonce
4. The random key is carried only in the **URL fragment** (`#` portion) — never
   sent to the server or stored in the database
5. Email addresses are stored as **SHA-256 hashes** — never in plaintext

---

## Requirements

| Tool | Version |
|------|---------|
| Go   | 1.26+   |

---

## Installation

```bash
go get github.com/bilustek/secretdropvault
```

---

## Usage

```go
package main

import (
	"fmt"
	"log"

	"github.com/bilustek/secretdropvault"
)

func main() {
	// 1. Generate a random key
	randomKey, err := secretdropvault.GenerateRandomKey()
	if err != nil {
		log.Fatal(err)
	}

	// 2. Derive an encryption key bound to the recipient
	recipient := "alice@example.com"
	encKey, err := secretdropvault.DeriveKey(randomKey, recipient)
	if err != nil {
		log.Fatal(err)
	}

	// 3. Encrypt
	secret := []byte("DB_PASSWORD=super-secret")
	ciphertext, nonce, err := secretdropvault.Encrypt(encKey, secret)
	if err != nil {
		log.Fatal(err)
	}

	// 4. Encode the random key for URL transport
	encoded := secretdropvault.EncodeKey(randomKey)
	fmt.Println("URL key fragment:", encoded)

	// --- recipient side ---

	// 5. Decode the key from the URL fragment
	decodedKey, err := secretdropvault.DecodeKey(encoded)
	if err != nil {
		log.Fatal(err)
	}

	// 6. Re-derive the encryption key
	decKey, err := secretdropvault.DeriveKey(decodedKey, recipient)
	if err != nil {
		log.Fatal(err)
	}

	// 7. Decrypt
	plaintext, err := secretdropvault.Decrypt(decKey, ciphertext, nonce)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Decrypted:", string(plaintext))
}
```

### Hashing emails

```go
hash := secretdropvault.HashEmail("alice@example.com")
// hex-encoded SHA-256, safe to store in DB
```

### Generating tokens

```go
token, err := secretdropvault.GenerateToken()
// base64url-encoded random token (16 bytes)
```

---

## API

| Function | Description |
|----------|-------------|
| `GenerateRandomKey()` | Generates a 32-byte cryptographically secure random key |
| `GenerateToken()` | Generates a random base64url-encoded token |
| `DeriveKey(key, info)` | Derives a 32-byte key via HKDF-SHA256 |
| `Encrypt(key, plaintext)` | AES-256-GCM encryption, returns ciphertext + nonce |
| `Decrypt(key, ciphertext, nonce)` | AES-256-GCM decryption |
| `HashEmail(email)` | Hex-encoded SHA-256 hash |
| `EncodeKey(key)` | Base64url encode (no padding) |
| `DecodeKey(encoded)` | Base64url decode (no padding) |

---

## Contributor(s)

* [Uğur "vigo" Özyılmazel](https://github.com/vigo) - Creator, maintainer

---

## Contribute

All PR's are welcome!

1. `fork` (https://github.com/bilustek/secretdropvault/fork)
1. Create your `branch` (`git checkout -b my-feature`)
1. `commit` yours (`git commit -am 'add some functionality'`)
1. `push` your `branch` (`git push origin my-feature`)
1. Than create a new **Pull Request**!

---

## License

This project is licensed under MIT

---

This project is intended to be a safe, welcoming space for collaboration, and
contributors are expected to adhere to the [code of conduct][coc].

[coc]: https://github.com/bilustek/secretdropvault/blob/main/CODE_OF_CONDUCT.md
