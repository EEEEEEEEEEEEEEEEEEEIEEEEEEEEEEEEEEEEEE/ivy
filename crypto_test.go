package ivy

import "testing"

func TestCrypto(t *testing.T) {
	crypto := new(Crypto)
	crypto.Init("abcdefghijklmnopqrstuvwxyz123456")
	badnonce := "&IV6q8NET6VYjgLz0yewah9XiJ8Rb5pYZFmG/AwJh@T8u7sztvmYcR6dX+wnBRMZe6qbGCWD3P"
	_, success := crypto.Decrypt(badnonce)
	if success == true {
		t.Error("Nonce should have failed decrypt")
	}

	badencrypt := "IV6q8NET6VYjgLz0yewah9XiJ8Rb5pYZFmG/AwJh@%T8u7sztvmYcR6dX+wnBRMZe6qbGCWD3P"
	_, success = crypto.Decrypt(badencrypt)
	if success == true {
		t.Error("Encrypt should have failed decrypt")
	}

	wrongencrypt := "IV6q8NET6VYjgLz0yewah9XiJ8Rb5pYZFmG/AwJh@88u7sztvmYcR6dX+wnBRMZe6qbGCWD3P"
	_, success = crypto.Decrypt(wrongencrypt)
	if success == true {
		t.Error("Encrypt should have failed decrypt")
	}
}
