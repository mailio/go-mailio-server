package mailiosmtp

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mailio/go-mailio-server/types/mailiosmtp"
	"github.com/stretchr/testify/assert"
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
	email := mailiosmtp.Mail{
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
		Attachments: []*mailiosmtp.SmtpAttachment{
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
	receivedMsg := mailiosmtp.Mail{
		From:                      mail.Address{Name: "John", Address: "john@doe.com"},
		To:                        []mail.Address{{Name: "Jane", Address: "jane@jane.com"}},
		Subject:                   "Testing mailio",
		BodyHTML:                  "<h1>Testing mailio</h1>",
		Timestamp:                 time.Now().UTC().UnixMilli(),
		BodyHTMLWithoutUnsafeTags: "<h1>Testing mailio</h1>",
		SpamVerdict:               &mailiosmtp.VerdictStatus{Status: "PASS"},
		VirusVerdict:              &mailiosmtp.VerdictStatus{Status: "PASS"},
		SpfVerdict:                &mailiosmtp.VerdictStatus{Status: "PASS"},
		DkimVerdict:               &mailiosmtp.VerdictStatus{Status: "PASS"},
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

	receivedMsg := mailiosmtp.Mail{
		From:                      mail.Address{Name: "spam person", Address: "spammer@spam.com"},
		To:                        []mail.Address{{Name: "Jane", Address: "jane@alice.com"}},
		Subject:                   "Testing mailio",
		BodyHTML:                  "<h1>Testing mailio</h1>",
		Timestamp:                 time.Now().UTC().UnixMilli(),
		BodyHTMLWithoutUnsafeTags: "<h1>Testing mailio</h1>",
		SpamVerdict:               &mailiosmtp.VerdictStatus{Status: "FAIL"},
		VirusVerdict:              &mailiosmtp.VerdictStatus{Status: "PASS"},
		SpfVerdict:                &mailiosmtp.VerdictStatus{Status: "FAIL"},
		DkimVerdict:               &mailiosmtp.VerdictStatus{Status: "NOT_AVAILABLE"},
		BodyText:                  "Testing mailio",
		MessageId:                 "123456",
		Attachments: []*mailiosmtp.SmtpAttachment{
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

// majority of test eml files taken from
func TestEmailParsingTextPlain(t *testing.T) {
	b, _ := os.ReadFile("test_data/testplain.eml")
	mail, err := ParseMime(b)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains("this message has just plain text", strings.ToLower(mail.BodyText)) {
		t.Fatalf("Expected body text to contain 'this message has just plain text'")
	}
	assert.Equal(t, "kien.pham@sendgrid.com", mail.From.Address)
}

func TestEmailParsingInlineAttachmentNestedMultipart(t *testing.T) {
	b, _ := os.ReadFile("test_data/inline-attachment_nested_multipart.eml")
	mail, err := ParseMime(b)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "kien.pham@sendgrid.com", mail.From.Address)

	if len(mail.Attachments) == 0 {
		t.Fatalf("Expected attachments to be present")
	}
	assert.Equal(t, "image/jpeg", mail.Attachments[0].ContentType)
	assert.Contains(t, mail.BodyHTML, mail.Attachments[0].ContentID)
}

func TestEmailParsingInlineAttachmentMultipart(t *testing.T) {
	b, _ := os.ReadFile("test_data/inline-attachment_multipart.eml")
	mail, err := ParseMime(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(mail.Attachments) == 0 {
		t.Fatalf("Expected attachments to be present")
	}
	assert.Contains(t, mail.BodyHTML, mail.Attachments[0].ContentID)
}

func TestEmailParsingAttachmentWithoutName(t *testing.T) {
	b, _ := os.ReadFile("test_data/attachment-without-name.eml")
	mail, err := ParseMime(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(mail.Attachments) == 0 {
		t.Fatalf("Expected attachments to be present")
	}
}

func TestEmailParsingRfc822(t *testing.T) {
	b, _ := os.ReadFile("test_data/rfc822.eml")
	mail, err := ParseMime(b)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "<201009131834.7e024c8ea6ecae@omr-m23.mx.aol.com>", mail.MessageId)
}

func TestEmailParsingMailioBounce(t *testing.T) {
	b, _ := os.ReadFile("test_data/mailio-bounce.eml")
	mail, err := ParseMime(b)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("mail: %v\n", mail)
}

func TestEmailParsingMultipeHeaders(t *testing.T) {
	b, _ := os.ReadFile("test_data/multiple-headers.eml")
	mail, err := ParseMime(b)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("mail: %v\n", mail)
}

func TestParseBounce(t *testing.T) {
	receivedMsg := mailiosmtp.Mail{
		From:                      mail.Address{Name: "John", Address: "john@doe.com"},
		To:                        []mail.Address{{Name: "Jane", Address: "jane@jane.com"}},
		Subject:                   "Testing mailio",
		BodyHTML:                  "<h1>Testing mailio</h1>",
		Timestamp:                 time.Now().UTC().UnixMilli(),
		BodyHTMLWithoutUnsafeTags: "<h1>Testing mailio</h1>",
		SpamVerdict:               &mailiosmtp.VerdictStatus{Status: "PASS"},
		VirusVerdict:              &mailiosmtp.VerdictStatus{Status: "PASS"},
		SpfVerdict:                &mailiosmtp.VerdictStatus{Status: "PASS"},
		DkimVerdict:               &mailiosmtp.VerdictStatus{Status: "PASS"},
		BodyText:                  "Testing mailio",
		MessageId:                 "123456",
	}
	bounceBytes, bErr := ToBounce(receivedMsg.To[0], receivedMsg, "5.1.1", "Recipient address rejected: User unknown in virtual mailbox table")
	if bErr != nil {
		t.Fatalf("toBounce failed: %v", bErr)
	}
	fmt.Printf("bounce: %s\n", string(bounceBytes))
	mail, err := ParseMime(bounceBytes)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, mail.MessageId, receivedMsg.MessageId)
}
