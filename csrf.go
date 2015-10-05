package ivy

import (
	"strconv"
	"strings"
	"time"
)

type CSRF struct {
	ic  Crypto
	ttl int64
}

// Init produces a CSRF which encrypts tokens, with
// the given key, that have a ttl matching the one given.
func (csrf *CSRF) Init(key string, ttl int64) {
	csrf.ic.Init(key)
	csrf.ttl = ttl
}

// Generate produces an encrpyted CSRF token comprising
// the discriminator and a timestamp representing when the token
// will expire.
// discriminator should be unique to the given user/session that is being checked.
func (csrf *CSRF) Generate(discriminator string) string {
	expiry := time.Now().Unix() + csrf.ttl
	return csrf.ic.Encrypt(strconv.Itoa(int(expiry)) + "|" + discriminator)
}

// Validate decrypts encryptedToken and checks that it contains the
// given discriminator, and that the token is valid given the ttl, if all
// are true the function returns true, otherwise false.
func (csrf *CSRF) Validate(encryptedToken string, discriminator string) bool {
	token, success := csrf.ic.Decrypt(encryptedToken)

	if !success {
		return false
	}

	s := strings.Split(token, "|")
	if len(s) != 2 || s[1] != discriminator {
		return false
	}

	expiry, err := strconv.ParseInt(s[0], 0, 64)
	if err != nil {
		return false
	}

	if expiry < time.Now().Unix() {
		return false
	}
	return true
}
