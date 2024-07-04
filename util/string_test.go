package util

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestHexEncode(t *testing.T) {
	str := "test"
	encoded := HexEncodeToString(str)
	if encoded != "74657374" {
		t.Errorf("Expected %s, got %s", "74657374", encoded)
	}
}

func TestHexEncodeDBUser(t *testing.T) {
	str := "userdb-" + HexEncodeToString("org.couchdb.user:bob")
	fmt.Printf("encoded: %s", str)
}

func TestBase64Decode(t *testing.T) {
	base64String := "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoib09XLVBoc3F6NFkwaVVWMGZHZXl4Yl9XbkxFUDVDNW5fQ0paT1JPTVAzVSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDIwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"
	base64String = strings.TrimRight(base64String, "=")
	switch len(base64String) % 4 {
	case 2:
		base64String += "=="
	case 3:
		base64String += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(base64String)
	if err != nil {
		t.Errorf("Error decoding base64: %s", err)
	}
	fmt.Printf("decoded: %s", decoded)
}
