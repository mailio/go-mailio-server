package mailiosmtp

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/mail"
	"testing"
	"time"

	"github.com/mailio/go-mailio-server/types"
)

func TestToMime(t *testing.T) {
	ripUrl := "https://upload.wikimedia.org/wikipedia/commons/3/38/JPEG_example_JPG_RIP_001.jpg"
	response, err := http.Get(ripUrl)
	if err != nil {
		log.Fatalf("Failed to download the image: %v", err)
	}
	defer response.Body.Close()
	imageData, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Failed to read the image data: %v", err)
	}
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
		Attachments: []*types.SmtpAttachment{
			{
				ContentType: "image/jpeg",
				Filename:    "lenna.jpg",
				Content:     imageData,
			},
		},
	}
	mime, err := ToMime(&email)
	if err != nil {
		t.Fatalf("toMime failed: %v", err)
	}
	fmt.Printf("mime: %s\n", string(mime))
}

func TestToBounce(t *testing.T) {
	receivedMsg := types.Mail{
		From:                      mail.Address{Name: "John", Address: "john@doe.com"},
		To:                        []mail.Address{{Name: "Jane", Address: "jane@jane.com"}},
		Subject:                   "Testing mailio",
		BodyHTML:                  "<h1>Testing mailio</h1>",
		Timestamp:                 time.Now().UTC().UnixMilli(),
		BodyHTMLWithoutUnsafeTags: "<h1>Testing mailio</h1>",
		SpamVerdict:               &types.VerdictStatus{Status: "PASS"},
		VirusVerdict:              &types.VerdictStatus{Status: "PASS"},
		SpfVerdict:                &types.VerdictStatus{Status: "PASS"},
		DkimVerdict:               &types.VerdictStatus{Status: "PASS"},
		BodyText:                  "Testing mailio",
		MessageId:                 "123456",
	}

	bounce, err := ToBounce(receivedMsg.To[0], receivedMsg, "5.1.1", "Recipient address rejected: User unknown in virtual mailbox table")
	if err != nil {
		t.Fatalf("toBounce failed: %v", err)
	}

	fmt.Printf("%s\n", string(bounce))
}

func TestToComplaint(t *testing.T) {
	ripUrl := "https://upload.wikimedia.org/wikipedia/commons/3/38/JPEG_example_JPG_RIP_001.jpg"
	response, err := http.Get(ripUrl)
	if err != nil {
		log.Fatalf("Failed to download the image: %v", err)
	}
	defer response.Body.Close()
	imageData, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Failed to read the image data: %v", err)
	}

	receivedMsg := types.Mail{
		From:                      mail.Address{Name: "spam person", Address: "spammer@spam.com"},
		To:                        []mail.Address{{Name: "Jane", Address: "jane@alice.com"}},
		Subject:                   "Testing mailio",
		BodyHTML:                  "<h1>Testing mailio</h1>",
		Timestamp:                 time.Now().UTC().UnixMilli(),
		BodyHTMLWithoutUnsafeTags: "<h1>Testing mailio</h1>",
		SpamVerdict:               &types.VerdictStatus{Status: "FAIL"},
		VirusVerdict:              &types.VerdictStatus{Status: "PASS"},
		SpfVerdict:                &types.VerdictStatus{Status: "FAIL"},
		DkimVerdict:               &types.VerdictStatus{Status: "NOT_AVAILABLE"},
		BodyText:                  "Testing mailio",
		MessageId:                 "123456",
		Attachments: []*types.SmtpAttachment{
			{
				ContentType: "image/jpeg",
				Filename:    "lenna.jpg",
				Content:     imageData,
			},
		},
	}

	complaintMime, err := ToComplaint(
		mail.Address{Name: "Complaint Department", Address: "complaints@myesp.com"},
		receivedMsg.To[0],
		receivedMsg,
		"spam/fraud/virus/...")
	if err != nil {
		t.Fatalf("toComplaint failed: %v", err)
	}
	fmt.Printf("%s\n", string(complaintMime))
}
