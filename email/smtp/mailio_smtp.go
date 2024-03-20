package mailiosmtp

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/mail"
	"net/textproto"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jhillyerd/enmime"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
	"github.com/microcosm-cc/bluemonday"
)

var (
	handlersMu       sync.RWMutex
	handlers         = make(map[string]SmtpHandler)
	maxBigInt        = big.NewInt(math.MaxInt64)
	bounceMailioInfo = "Mailio"
)

type SmtpHandler interface {
	// ReceiveMail is a method called on the specific ESP handler webhook implementation
	ReceiveMail(request http.Request) (*types.Mail, error)
	// SendMimeMail returns generated message id or error
	SendMimeMail(mime []byte, to []mail.Address) (string, error)
}

// RegisterSmtpHandler makes a smtp handler available by the provided name.
// If RegisterSmtpHandler is called twice with the same name or if driver is nil,
// it panics.
func RegisterSmtpHandler(name string, h SmtpHandler) {
	handlersMu.Lock()
	defer handlersMu.Unlock()
	if h == nil {
		panic("smtp: Register handler is nil")
	}
	if _, dup := handlers[name]; dup {
		panic("smtp: Register called twice for handler " + name)
	}
	handlers[name] = h
}

// for tests only
func unregisterAllHandlers() {
	handlersMu.Lock()
	defer handlersMu.Unlock()
	// For tests.
	handlers = make(map[string]SmtpHandler)
}

// Drivers returns a sorted list of the names of the registered drivers.
func Handlers() []string {
	handlersMu.RLock()
	defer handlersMu.RUnlock()
	list := make([]string, 0, len(handlers))
	for name := range handlers {
		list = append(list, name)
	}
	sort.Strings(list)
	return list
}

func htmlToText(html string) string {
	p := bluemonday.NewPolicy()
	p.AllowStandardURLs()
	// Remove all tags to leave only text
	clean := p.Sanitize(html)
	clean = strings.ReplaceAll(clean, "\n", "")
	clean = strings.ReplaceAll(clean, "\t", " ")
	clean = strings.ReplaceAll(clean, "  ", " ")
	clean = strings.TrimSpace(clean)
	words := strings.Fields(clean)
	clean = strings.Join(words, " ")
	return clean
}

// GenerateMessageID generates and returns a string suitable for an RFC 2822
// compliant Message-ID, e.g.:
// <1444789264909237300.3464.1819418242800517193@DESKTOP01>
//
// The following parameters are used to generate a Message-ID:
// - The nanoseconds since Epoch
// - The calling PID
// - A cryptographically random int64
// - The sending hostname
func generateRFC2822MessageID(hostname string) (string, error) {
	t := time.Now().UnixNano()
	pid := os.Getpid()
	rint, err := rand.Int(rand.Reader, maxBigInt)
	if err != nil {
		return "", err
	}
	if hostname == "" {
		return "", types.ErrInvalidFormat
	}
	msgid := fmt.Sprintf("<%d.%d.%d@%s>", t, pid, rint, hostname)
	return msgid, nil
}

// converts a message to a mime message
func ToMime(msg *types.Mail) ([]byte, error) {

	// convert html to text
	text := htmlToText(msg.BodyHTML)

	// construct basic message
	outgoingMime := enmime.Builder().
		From(msg.From.Name, msg.From.Address).
		Subject(msg.Subject).
		ToAddrs(msg.To).
		ReplyToAddrs(msg.ReplyTo).
		Text([]byte(text)).
		Date(time.UnixMilli(msg.Timestamp)).
		HTML([]byte(msg.BodyHTML))

	// add sender address if present
	if msg.Cc != nil {
		outgoingMime = outgoingMime.CCAddrs(msg.Cc)
	}
	if msg.Bcc != nil {
		outgoingMime = outgoingMime.BCCAddrs(msg.Bcc)
	}

	// add headers
	outgoingMime = outgoingMime.Header("X-Mailer", "Mailio")

	// add message id
	host := "localhost"
	if global.Conf.Host != "" {
		host = global.Conf.Host
	}
	id, idErr := generateRFC2822MessageID(host)
	if idErr != nil {
		global.Logger.Log("error", "error generating message id", "error", idErr)
		return nil, idErr
	}
	outgoingMime = outgoingMime.Header("Message-ID", id)

	// build and encode the message
	ep, err := outgoingMime.Build()
	if err != nil {
		global.Logger.Log("error", "error building mime message", "error", err)
		return nil, err
	}
	var buf bytes.Buffer
	err = ep.Encode(&buf)
	if err != nil {
		global.Logger.Log("error", "error encoding mime message", "error", err)
		return nil, err
	}

	return buf.Bytes(), nil
}

/*
Recommeneded to handle the following bounce reasons:
Mailbox Does Not Exist — SMTP Reply Code = 550, SMTP Status Code = 5.1.1
Message Too Large — SMTP Reply Code = 552, SMTP Status Code = 5.3.4
Mailbox Full — SMTP Reply Code = 552, SMTP Status Code = 5.2.2
Message Content Rejected — SMTP Reply Code = 500, SMTP Status Code = 5.6.1
Unknown Failure — SMTP Reply Code = 554, SMTP Status Code = 5.0.0
Temporary Failure — SMTP Reply Code = 450, SMTP Status Code = 4.0.0

where 4.x.x codes are soft bounces, and 5.x..x codes are hard bounces
*/
func ToBounce(recipient mail.Address, msg types.MailSmtpReceived, bounceCode string, bounceReason string) ([]byte, error) {
	// Create the bounce message builder
	host := "localhost"
	if global.Conf.Host != "" {
		host = global.Conf.Host
	}
	from := mail.Address{Name: "Mailer-Daemon", Address: fmt.Sprintf("MAILER-DAEMON@%s", host)}

	// buffer to hold the headers temporarily
	var headerBuf bytes.Buffer

	// buffer to hold MIME message
	var buf bytes.Buffer

	// Create a multipart writer for the buffer, set to multipart/mixed
	writer := multipart.NewWriter(&buf)
	defer writer.Close()

	// Create the top-level header of the message
	header := make(textproto.MIMEHeader)
	header.Set("From", from.String())
	header.Set("To", recipient.String())
	header.Set("Subject", "Delivery Status Notification (Failure)")
	header.Set("Date", time.Now().Format(time.RFC1123Z))
	header.Set("MIME-Version", "1.0")
	header.Set("Content-Type", fmt.Sprintf("multipart/report; report-type=delivery-status; boundary=\"%s\"", writer.Boundary()))

	// Write the top-level headers to the temporary buffer
	for k, v := range header {
		fmt.Fprintf(&headerBuf, "%s: %s\r\n", k, strings.Join(v, ","))
	}

	// First part: Human-readable explanation of the bounce
	textPartHeader := make(textproto.MIMEHeader)
	textPartHeader.Set("Content-Type", "text/plain; charset=\"utf-8\"")
	textPart, _ := writer.CreatePart(textPartHeader)
	fmt.Fprintln(textPart, fmt.Sprintf("The following message to %s was undeliverable.\n\n"+
		"The reason for the problem:\n"+
		"%s - %s\n", recipient.String(), bounceCode, bounceReason))

	// Second part: Machine-readable delivery status
	dsnPartHeader := make(textproto.MIMEHeader)
	dsnPartHeader.Set("Content-Type", "message/delivery-status")
	dsnPart, _ := writer.CreatePart(dsnPartHeader)
	fmt.Fprintln(dsnPart, fmt.Sprintf("Reporting-MTA: dns; %s"+
		"\nArrival-Date: "+time.Now().UTC().Format(time.RFC1123Z)+"\n\n"+
		"Final-Recipient: rfc822; %s"+
		"\nAction: failed"+
		"\nStatus:%s"+
		"\nRemote-MTA: dns; %s"+
		"\nDiagnostic-Code: smtp; %s - %s", host, recipient.String(), bounceCode, host, bounceCode, bounceReason))

	// add original message
	// Third part: Original message headers and body
	originalPartHeader := make(textproto.MIMEHeader)
	originalPartHeader.Set("Content-Type", "message/rfc822")
	originalPart, _ := writer.CreatePart(originalPartHeader)
	fmt.Fprintf(originalPart, "From: %s\nTo: %s\nSubject: %s\nDate: %s\n\n%s", msg.From.String(), recipient.String(), msg.Subject, time.Now().UTC().Format(time.RFC1123Z), "The original message was not included in this report.")

	// Close the multipart writer to finalize the boundary
	if err := writer.Close(); err != nil {
		fmt.Println("Error closing writer:", err)
		return nil, err
	}

	// Combine headers and body
	var finalBuf bytes.Buffer
	finalBuf.Write(headerBuf.Bytes())
	finalBuf.WriteString("\r\n") // Important: Separate headers from body with an empty line
	finalBuf.Write(buf.Bytes())

	return finalBuf.Bytes(), nil
}

func ToComplaint(recipient mail.Address, complaintReason string) ([]byte, error) {
	// Set host dynamically or use "localhost" as default
	host := "localhost"
	if global.Conf.Host != "" {
		host = global.Conf.Host
	}
	from := mail.Address{Name: "Complaint Department", Address: fmt.Sprintf("complaints@%s", host)}

	// Buffers for headers and MIME message
	var headerBuf bytes.Buffer
	var buf bytes.Buffer

	// Create a multipart writer for the MIME message buffer
	writer := multipart.NewWriter(&buf)
	defer writer.Close()

	// Set the top-level headers for the message
	header := make(textproto.MIMEHeader)
	header.Set("From", from.String())
	header.Set("To", recipient.String())
	header.Set("Subject", "Complaint Notification")
	header.Set("Date", time.Now().Format(time.RFC1123Z))
	header.Set("MIME-Version", "1.0")
	header.Set("Content-Type", fmt.Sprintf("multipart/report; report-type=complaint-feedback-report; boundary=\"%s\"", writer.Boundary()))

	// Write the top-level headers to the temporary buffer
	for k, v := range header {
		fmt.Fprintf(&headerBuf, "%s: %s\r\n", k, strings.Join(v, ","))
	}

	// First part: Human-readable explanation of the complaint
	textPartHeader := make(textproto.MIMEHeader)
	textPartHeader.Set("Content-Type", "text/plain; charset=\"utf-8\"")
	textPart, _ := writer.CreatePart(textPartHeader)
	fmt.Fprintln(textPart, fmt.Sprintf("This message is to inform you that a complaint was received for an email sent to %s.\n\n"+
		"Reason for complaint:\n"+
		"%s\n", recipient.String(), complaintReason))

	// Second part: Machine-readable complaint feedback report
	feedbackPartHeader := make(textproto.MIMEHeader)
	feedbackPartHeader.Set("Content-Type", "message/feedback-report")
	feedbackPart, _ := writer.CreatePart(feedbackPartHeader)
	fmt.Fprintln(feedbackPart, fmt.Sprintf("Feedback-Type: complaint\n"+
		"User-Agent: %s\n"+
		"Version: 1\n"+
		"Original-Recipient: rfc822; %s\n"+
		"Final-Recipient: rfc822; %s\n"+
		"Original-Mail-From: %s\n"+
		"Arrival-Date: %s\n"+
		"Reported-Domain: %s\n"+
		"Reason: %s", host, recipient.String(), recipient.String(), from.String(), time.Now().UTC().Format(time.RFC1123Z), host, complaintReason))

	// Close the multipart writer to finalize the boundary
	if err := writer.Close(); err != nil {
		fmt.Println("Error closing writer:", err)
		return nil, err
	}

	// Combine headers and body
	var finalBuf bytes.Buffer
	finalBuf.Write(headerBuf.Bytes())
	finalBuf.WriteString("\r\n") // Separate headers from body with an empty line
	finalBuf.Write(buf.Bytes())

	return finalBuf.Bytes(), nil
}
