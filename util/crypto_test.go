package util

import (
	"encoding/base64"
	"testing"

	"github.com/mailio/go-mailio-server/global"
	"github.com/tj/assert"
)

func TestScryptEmail(t *testing.T) {
	global.Conf.Mailio = global.MailioConfig{
		EmailSaltHex: "1234567890",
	}
	scrypted, err := ScryptEmail("test@test.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(scrypted) != 32 {
		t.Fatal("scrypted email is not 32 bytes long")
	}
}

func TestGenerateKeyPair(t *testing.T) {

	pub, priv, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pubKey, kErr := base64.StdEncoding.DecodeString(*pub)
	if kErr != nil {
		t.Fatal(kErr)
	}
	privKey, kErr := base64.StdEncoding.DecodeString(*priv)
	if kErr != nil {
		t.Fatal(kErr)
	}
	if len(pubKey) != 32 {
		t.Fatal("invalid public key length")
	}
	if len(privKey) != 64 {
		t.Fatal("invalid private key length")
	}
}

func TestSignMessage(t *testing.T) {
	pub, priv, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	base64Priv, _ := base64.StdEncoding.DecodeString(*priv)
	message := []byte("hello world")
	signature, err := Sign(message, base64Priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) != 64 {
		t.Fatal("invalid signature length")
	}
	verified, err := Verify(message, signature, *pub)
	if err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Fatal("invalid signature")
	}
}

func TestPubKeyToMailioAddress(t *testing.T) {
	pub, _, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rawPub, _ := base64.StdEncoding.DecodeString(*pub)
	address, err := PublicKeyToMailioAddress(rawPub)
	if err != nil {
		t.Fatal(err)
	}
	valid := IsValidMailioAddress(address)
	if !valid {
		t.Fatal("invalid address")
	}
}

func TestEqualityOfCreatingMailioAddress(t *testing.T) {
	// rawKey, _ := base64.RawURLEncoding.DecodeString("lTi99FcVgGAuoHblyw0pffGs3GwZudOT3XDjZ9d7cKc=")
	rawKey, _ := base64.StdEncoding.DecodeString("lTi99FcVgGAuoHblyw0pffGs3GwZudOT3XDjZ9d7cKc=")
	address, err := PublicKeyToMailioAddress(rawKey)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "0xfe664890e83e8e41cc19317e14803097eaa1ead1", address)
}
