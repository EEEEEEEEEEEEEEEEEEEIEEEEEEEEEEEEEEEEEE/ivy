package ivy

import "testing"
import "time"

func TestCSRF(t *testing.T) {
	csrf := new(CSRF)
	csrf.Init("abcdefghijklmnopqrstuvwxyz123456", 10)
	token := csrf.Generate("Hello")
	if csrf.Validate(token, "Hello") == false {
		t.Errorf("CSRF token %s was not Valid", token)
	}
}

func TestCSRFTimeout(t *testing.T) {
	csrf := new(CSRF)
	csrf.Init("abcdefghijklmnopqrstuvwxyz123456", 1)
	token := csrf.Generate("Hello")
	time.Sleep(2 * time.Second)
	if csrf.Validate(token, "Hello") != false {
		t.Errorf("CSRF token %s was Valid, should have expired", token)
	}
}

func TestCSRFIncorrectDiscriminator(t *testing.T) {
	csrf := new(CSRF)
	csrf.Init("abcdefghijklmnopqrstuvwxyz123456", 10)
	token := csrf.Generate("Hello")
	if csrf.Validate(token, "Invalid") != false {
		t.Errorf("CSRF token %s was Valid, should have failed", token)
	}
}

func TestCSRFIncorrectToken(t *testing.T) {
	csrf := new(CSRF)
	csrf.Init("abcdefghijklmnopqrstuvwxyz123456", 10)

	if csrf.Validate("NOT A REAL TOKEN", "Invalid") != false {
		t.Errorf("CSRF token was Valid, should have failed")
	}
}

func TestCSRFIncorrectExpiry(t *testing.T) {
	crypto := new(Crypto)
	crypto.Init("abcdefghijklmnopqrstuvwxyz123456")
	csrf := new(CSRF)
	csrf.Init("abcdefghijklmnopqrstuvwxyz123456", 10)
	if csrf.Validate(crypto.Encrypt("AA|Invalid"), "Invalid") != false {
		t.Errorf("CSRF token was Valid, should have failed")
	}
}
