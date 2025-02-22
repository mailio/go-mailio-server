package util

import (
	"encoding/base64"
	"testing"

	"github.com/mailio/go-mailio-server/global"
	"github.com/tj/assert"
)

func TestScryptEmail(t *testing.T) {
	global.Conf.Mailio = global.MailioConfig{}
	scrypted, err := ScryptEmail("test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	decoded, dErr := base64.StdEncoding.DecodeString(scrypted)
	if dErr != nil {
		t.Fatal(dErr)
	}
	if len(decoded) != 32 {
		t.Fatal("scrypted email is not 32 bytes long")
	}
	assert.Equal(t, "ymswrp83Dy79wmX+OKRNqWXP2KiT75k0l4YRDE3sdiA=", scrypted)
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
