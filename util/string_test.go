package util

import (
	"fmt"
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
