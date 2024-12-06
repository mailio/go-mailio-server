package util

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/mailio/go-mailio-server/types"
	"github.com/stretchr/testify/assert"
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

func TestCBORExample(t *testing.T) {
	example := &types.Handshake{
		Content: types.HandshakeContent{
			HandshakeID: "1234567890",
			OriginServer: types.OriginServer{
				Domain: "test.mail.io",
			},
			Created: float64(time.Now().UnixMilli()),
		},
		SignatureBase64:   "123",
		CborPayloadBase64: "123",
	}
	encoded, err := base64.StdEncoding.DecodeString("uQAKa2hhbmRzaGFrZUlkeEBhNzA3YmJlN2VkMjJmOTExYjA1YmQwMTFlOTQ3NjAwYzI4ZmZkMjQ4ZjU1OWVkZDFhYTE4MDFjMmJmMjM4MDIzbG9yaWdpblNlcnZlcrkAAWZkb21haW5ubG9jYWxob3N0OjgwODBkdHlwZWR1c2VyZnN0YXR1c2hhY2NlcHRlZGVsZXZlbGRub25lbm93bmVyUHVibGljS2V5eCxKWmdGZWpOalZhMlc3c09DcXN0RUk3TWNiREVld3cvdHFZd3B5clpxUmtZPWxvd25lckFkZHJlc3N4KjB4MTg2OWNjMDU4MDkyMzE3ODAwNzI3YWZhMjU5ODFiZmQyYTNkMDk2OWdjcmVhdGVk+0J44GTh2PAAbnNlbmRlck1ldGFkYXRhuQABaWVtYWlsSGFzaHgsbVArYkxwY2x0Mk5iQ1dUVkdmZU1zclpnZUhwcklranZqbWo4cjVaNGdRQT1vc2lnbmF0dXJlU2NoZW1lbEVkRFNBX1gyNTUxOQ==")
	if err != nil {
		t.Fatal(err)
	}
	// encoded, err := CborEncode(example)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	decoded := &types.Handshake{}
	err = CborDecode(encoded, decoded)
	if err != nil {
		t.Fatal(err)
	}
	if example.Content.Created != decoded.Content.Created {
		t.Fatal("created not equal")
	}
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
			OriginServer: types.OriginServer{Domain: "test.mail.io"},
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

func TestHandshakeCreateID(t *testing.T) {
	ownerAddress := "0xded2c4bd132eb661000f790c13c30b1fe93b7800"
	sender := "did:web:localhost:8080#0xbd5892c986679c803c55322a297778eeee30c84c"
	id := "2a69191be05ed96d7107982d7e15bb576061950fc17d6b9137ed28309d99fb69"

	handshakeIDConcat := ownerAddress + sender
	s256 := sha256.Sum256([]byte(handshakeIDConcat))
	handshakeID := hex.EncodeToString(s256[:])

	assert.Equal(t, handshakeID, id)
}
