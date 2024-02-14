package util

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"testing"

	"github.com/mailio/go-mailio-server/types"
)

var (
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
)

func init() {
	// Generate a key pair
	pub, priv, err := GenerateEd25519KeyPair()
	if err != nil {
		log.Fatal(err)
	}
	pubKey, kErr := base64.StdEncoding.DecodeString(*pub)
	if kErr != nil {
		log.Fatal(kErr)
	}
	privKey, kErr := base64.StdEncoding.DecodeString(*priv)
	if kErr != nil {
		log.Fatal(kErr)
	}
	publicKey = pubKey
	privateKey = privKey
}

func TestServerHandshake(t *testing.T) {
	// TestServerHandshake tests the server handshake
	srvKey, err := ServerSideHandshake(publicKey, privateKey, "test.example.com")
	if err != nil {
		t.Fatal(err)
	}
	prettyJson, _ := json.MarshalIndent(srvKey, "", "  ")
	fmt.Printf("Server handshake: %v\n", string(prettyJson))
}

func TestVerifyServerSideHandshake(t *testing.T) {
	handshake, err := ServerSideHandshake(publicKey, privateKey, "test.mail.io")
	if err != nil {
		t.Fatal(err)
	}

	isValid, vErr := VerifyHandshake(handshake, base64.StdEncoding.EncodeToString(publicKey))
	if vErr != nil {
		t.Fatal(vErr)
	}
	if !isValid {
		t.Fatal("not valid handshake")
	}

}

func TestCBOR(t *testing.T) {
	example := types.Handshake{
		Content: types.HandshakeContent{
			HandshakeID:  "1234567890",
			OriginServer: types.HandshakeOriginServer{Domain: "test.mail.io"},
		},
		// SignatureBase64:   "123",
		// CborPayloadBase64: "123",

		// Header: models.HandshakeHeader{
		// 	SignatureScheme:         "124",
		// 	EmailLookupScryptScheme: "a23c",
		// 	Created:                 time.Now(),
		// },
		// Lookup: []models.HandshakeLookup{
		// 	{
		// 		HandshakeID:       "1234567890",
		// 		ScryptLookupEmail: "abc@mail.io",
		// 		Address:           "0xabc",
		// 	},
		// },
	}

	var previous []byte
	for i := 0; i < 1000; i++ {
		// b, err := cbor.Marshal(example)
		b, err := CborEncode(example)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			previous = b
			continue
		}

		if !bytes.Equal(previous, b) {
			t.Fatal("not equal")
		}

		previous = b
	}
}
