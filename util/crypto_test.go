package util

import "testing"

func TestScryptEmail(t *testing.T) {
	scrypted, err := ScryptEmail("test@test.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(scrypted) != 32 {
		t.Fatal("scrypted email is not 32 bytes long")
	}
}
