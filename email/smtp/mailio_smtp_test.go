package mailiosmtp

import (
	"fmt"
	"net/mail"
	"testing"
	"time"

	"github.com/mailio/go-mailio-server/types"
)

func TestToMime(t *testing.T) {
	email := types.Mail{
		From: mail.Address{
			Name:    "John Doe",
			Address: "test@test.com",
		},
		To: []mail.Address{
			{
				Address: "mail@test.com",
			},
		},
		Subject:   "Testing mailio",
		BodyHTML:  "<h1>Testing mailio</h1>",
		Timestamp: time.Now().UTC().UnixMilli(),
	}
	mime, err := ToMime(&email)
	if err != nil {
		t.Fatalf("toMime failed: %v", err)
	}
	fmt.Printf("mime: %s\n", string(mime))
}

func TestToBounce(t *testing.T) {
	receivedMsg := types.MailSmtpReceived{
		From:                     mail.Address{Name: "John", Address: "john@doe.com"},
		To:                       []mail.Address{{Name: "Jane", Address: "jane@jane.com"}},
		Subject:                  "Testing mailio",
		BodyHTML:                 "<h1>Testing mailio</h1>",
		Timestamp:                time.Now().UTC().UnixMilli(),
		BodyHTMWithoutUnsafeTags: "<h1>Testing mailio</h1>",
		SpamVerdict:              &types.VerdictStatus{Status: "PASS"},
		VirusVerdict:             &types.VerdictStatus{Status: "PASS"},
		SpfVerdict:               &types.VerdictStatus{Status: "PASS"},
		DkimVerdict:              &types.VerdictStatus{Status: "PASS"},
		BodyText:                 "Testing mailio",
		MessageId:                "123456",
	}

	bounce, err := ToBounce(receivedMsg.To[0], receivedMsg, "5.1.1", "Recipient address rejected: User unknown in virtual mailbox table")
	if err != nil {
		t.Fatalf("toBounce failed: %v", err)
	}

	fmt.Printf("%s\n", string(bounce))
}
