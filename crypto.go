package ivy

import (
	"crypto/rand"
	"encoding/base64"
	"golang.org/x/crypto/nacl/secretbox"
	"strings"
)

type Crypto struct {
	key [32]byte
}

func (ic *Crypto) Init(key string) {
	copy(ic.key[:], key)
}

// Encrypt encrypts the plaintext message given the key associated with the Crypto object and
// returns the encrypted output.
func (ic *Crypto) Encrypt(message string) string {
	var nonce [24]byte
	rand.Reader.Read(nonce[:]) // should check that you actually read in practice

	var encrypted []byte
	encrypted = secretbox.Seal(encrypted, []byte(message), &nonce, &ic.key)
	return base64.StdEncoding.EncodeToString(encrypted) + "@" + base64.StdEncoding.EncodeToString(nonce[:])
}

// Decrypt decrypts the encrypted message given the key associated with the Crypto object and
// returns, if successful, the plaintext message.
func (ic *Crypto) Decrypt(message string) (string, bool) {
	s := strings.Split(message, "@")

	// Sanity Check the Structure
	if len(s) != 2 {
		return "Structure is invalid.", false
	}

	// Decode the Nonce
	var nonce [24]byte
	decodednonce, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return "Cannot base64 decode nonce", false
	}
	copy(nonce[:], decodednonce)

	// Decode the Message
	encrypted, err := base64.StdEncoding.DecodeString(s[0])
	if err != nil {
		return "Cannot base64 decode message", false
	}

	var decrypted []byte
	decrypted, success := secretbox.Open(decrypted, []byte(encrypted), &nonce, &ic.key)
	if !success {
		return "Failed to decrypt", false
	}
	return string(decrypted), true
}
