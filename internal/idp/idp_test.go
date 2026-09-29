package idp

import (
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestHashPassword_IsAnArgon2idStringAutheliaVerifies(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	// $argon2id$v=19$m=65536,t=3,p=4$SALT$KEY, Authelia's default shape.
	parts := strings.Split(h, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=65536,t=3,p=4" {
		t.Fatalf("hash %q is not the argon2id PHC form Authelia reads", h)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != 16 {
		t.Fatalf("salt %q: %v (len %d)", parts[4], err, len(salt))
	}
	want := base64.RawStdEncoding.EncodeToString(argon2.IDKey([]byte("correct horse battery staple"), salt, 3, 65536, 4, 32))
	if parts[5] != want {
		t.Fatal("the key is not argon2id of the password under the stated parameters")
	}
	if h2, _ := HashPassword("correct horse battery staple"); h2 == h {
		t.Fatal("two hashes of one password share a salt")
	}
}

func TestGeneratePassword_IsLongAndUnambiguous(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		p, err := GeneratePassword()
		if err != nil {
			t.Fatal(err)
		}
		if len(p) < 20 || strings.ContainsAny(p, "0O1lI") || seen[p] {
			t.Fatalf("password %q: too short, ambiguous, or repeated", p)
		}
		seen[p] = true
	}
}

func TestValidateAccount_RefusesWhatAnOperatorCouldNotHaveMeant(t *testing.T) {
	ok := Account{Username: "ana.souza", DisplayName: "Ana Souza", Email: "ana@example.org", Groups: []string{"blue-ir"}}
	if err := ValidateAccount(ok); err != nil {
		t.Fatalf("valid account refused: %v", err)
	}
	for name, a := range map[string]Account{
		"empty username":        {Username: "", DisplayName: "x"},
		"uppercase username":    {Username: "Ana", DisplayName: "x"},
		"space in username":     {Username: "ana souza", DisplayName: "x"},
		"yaml-looking username": {Username: "ana: x", DisplayName: "x"},
		"control in name":       {Username: "ana", DisplayName: "Ana\u202e"},
		"empty display name":    {Username: "ana", DisplayName: " "},
		"bad email":             {Username: "ana", DisplayName: "Ana", Email: "not an email"},
		"newline in group":      {Username: "ana", DisplayName: "Ana", Groups: []string{"blue\nir"}},
	} {
		if err := ValidateAccount(a); err == nil {
			t.Errorf("%s: accepted %+v", name, a)
		}
	}
}
