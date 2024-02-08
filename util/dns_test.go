package util

import (
	"context"
	"fmt"
	"testing"

	"github.com/mailio/go-mailio-server/types"
	"github.com/stretchr/testify/assert"
)

const DOMAIN = "mail.io"

// the test uses mail.io for testing
func TestDiscover(t *testing.T) {
	discover, err := MailioDNSDiscover(context.Background(), DOMAIN)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, discover.Domain, DOMAIN)
	assert.Equal(t, discover.IsMailio, true)
	assert.Equal(t, discover.PublicKeyType, "ed25519")
}

func TestPublicKey(t *testing.T) {
	key := "5uW7anEGF1nIjGfp5pS2kiN0cn2mGYkuSa+TCBoFIbQ="
	pkErr := validatePublicKeyLength(key)
	if pkErr != nil {
		t.Fatal(pkErr)
	}
}

func TestPublicKeyTooShort(t *testing.T) {
	key := "" // valid base64
	pkErr := validatePublicKeyLength(key)
	assert.Equal(t, pkErr, types.ErrInvalidPublicKey)
}

func TestPublicKeyInvalidBase64(t *testing.T) {
	pub, _, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	record, err := GenerateTXTRecord(DOMAIN, *pub)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("TXT record: %s\n", *record)
}
