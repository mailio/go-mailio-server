package util

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
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
	message := []byte("hello world")
	signature, err := Sign(message, *priv)
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
	address, err := PublicKeyToMailioAddress(*pub)
	if err != nil {
		t.Fatal(err)
	}
	valid := IsValidMailioAddress(address)
	if !valid {
		t.Fatal("invalid address")
	}
}

func TestEqualityOfCreatingMailioAddress(t *testing.T) {
	address, err := PublicKeyToMailioAddress("lTi99FcVgGAuoHblyw0pffGs3GwZudOT3XDjZ9d7cKc=")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "0xfe664890e83e8e41cc19317e14803097eaa1ead1", address)
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

		if bytes.Equal(previous, b) {
			fmt.Printf("equal %d\n", i)
		} else {
			t.Fatal("not equal")
		}

		previous = b
	}
}

func TestHandshakeValidity(t *testing.T) {
	jsonStr := `
	{
		"content": {
		  "handshakeId": "0d9dacbe2fa364fe8477e116ebd651f2f41649a0b5413a151bc3fc10fbb93da6",
		  "originServer": {
			"domain": "test.mail.io"
		  },
		  "type": 1,
		  "status": 0,
		  "level": 0,
		  "ownerPublicKey": "lTi99FcVgGAuoHblyw0pffGs3GwZudOT3XDjZ9d7cKc=",
		  "ownerAddress": "0xfe664890e83e8e41cc19317e14803097eaa1ead1",
		  "created": 1691256884935,
		  "signatureScheme": 1
		},
		"signatureBase64": "uJs+M28IBwOOfz730z+iay5Y++KrRsw0hVAhbSNqr63g6kM2T03OpSKg2oBwLWbBgV/sIGNiMoyaPQV35FBNAg==",
		"cborPayloadBase64": "uQAJa2hhbmRzaGFrZUlkeEAwZDlkYWNiZTJmYTM2NGZlODQ3N2UxMTZlYmQ2NTFmMmY0MTY0OWEwYjU0MTNhMTUxYmMzZmMxMGZiYjkzZGE2bG9yaWdpblNlcnZlcrkAAWZkb21haW5sdGVzdC5tYWlsLmlvZHR5cGUBZnN0YXR1cwBlbGV2ZWwAbm93bmVyUHVibGljS2V5eCxsVGk5OUZjVmdHQXVvSGJseXcwcGZmR3MzR3dadWRPVDNYRGpaOWQ3Y0tjPWxvd25lckFkZHJlc3N4KjB4ZmU2NjQ4OTBlODNlOGU0MWNjMTkzMTdlMTQ4MDMwOTdlYWExZWFkMWdjcmVhdGVk+0J4nGxA7HAAb3NpZ25hdHVyZVNjaGVtZQE="
	  }
	`
	var data types.Handshake
	// Unmarshal JSON data into the map
	err := json.Unmarshal([]byte(jsonStr), &data)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%+v\n", data)
	isValid, vErr := VerifyHandshake(&data, data.Content.OwnerPublicKeyBase64)
	if vErr != nil {
		t.Fatal(vErr)
	}
	if !isValid {
		t.Fatal("not valid handshake")
	}
}

func TestServerSideHandshake(t *testing.T) {
	pub, priv, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	handshake, err := ServerSideHandshake(*pub, *priv, "test.mail.io", "0xabc")
	if err != nil {
		t.Fatal(err)
	}

	isValid, vErr := VerifyHandshake(handshake, *pub)
	if vErr != nil {
		t.Fatal(vErr)
	}
	if !isValid {
		t.Fatal("not valid handshake")
	}

}
