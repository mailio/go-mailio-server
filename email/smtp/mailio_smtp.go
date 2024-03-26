package mailiosmtp

import (
	"bytes"
	"crypto/rand"
	"errors"
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
	"github.com/mailio/go-mailio-server/types/mailiosmtp"
	"github.com/microcosm-cc/bluemonday"
)

var (
	handlersMu sync.RWMutex
	handlers   = make(map[string]SmtpHandler)
	maxBigInt  = big.NewInt(math.MaxInt64)
)

type SmtpHandler interface {
	// ReceiveMail is a method called on the specific ESP handler webhook implementation
	ReceiveMail(request http.Request) (*mailiosmtp.Mail, error)
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
func ToMime(msg *mailiosmtp.Mail) ([]byte, error) {

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

	// add attachments
	if msg.Attachments != nil {
		for _, attachment := range msg.Attachments {
			outgoingMime = outgoingMime.AddAttachment(attachment.Content, attachment.ContentType, attachment.Filename)
		}

	}

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
func ToBounce(recipient mail.Address, msg mailiosmtp.Mail, bounceCode string, bounceReason string) ([]byte, error) {
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
	header.Set("Message-ID", msg.MessageId)
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

// ToComplaint creates a complaint message
/*
Complaints are generated when a recipient reports an email as spam or junk.
The recipient's email provider sends a complaint to the custom ESP.
The complaint includes the original email that was reported as spam or junk.
The complaint also includes information about the recipient who reported the email as spam or junk.

https://en.wikipedia.org/wiki/Abuse_Reporting_Format
https://datatracker.ietf.org/doc/html/rfc5965
*/
func ToComplaint(recipient mail.Address, reporter mail.Address, msg mailiosmtp.Mail, complaintReason string) ([]byte, error) {
	// Set host dynamically or use "localhost" as default
	host := "localhost"
	if global.Conf.Host != "" {
		host = global.Conf.Host
	}

	// Convert the original message to MIME
	originalMsgMime, err := ToMime(&msg)
	if err != nil {
		return nil, err
	}

	// Buffers for headers and MIME message
	var headerBuf bytes.Buffer
	var buf bytes.Buffer

	// Create a multipart writer for the MIME message buffer
	writer := multipart.NewWriter(&buf)
	defer writer.Close()

	// Set the top-level headers for the message
	header := make(textproto.MIMEHeader)
	header.Set("From", reporter.String())
	header.Set("To", recipient.String())
	header.Set("Subject", "Complaint Notification")
	header.Set("Date", time.Now().Format(time.RFC1123Z))
	header.Set("MIME-Version", "1.0")
	header.Set("Content-Type", fmt.Sprintf("multipart/report; report-type=complaint-feedback-report; boundary=\"%s\"", writer.Boundary()))

	// Write the top-level headers to the temporary buffer
	for k, v := range header {
		fmt.Fprintf(&headerBuf, "%s: %s\r\n", k, strings.Join(v, ","))
	}

	allTos := ""
	for i, to := range msg.To {
		allTos += to.String()
		if i < len(msg.To)-1 {
			allTos += ", "
		}
	}
	for i, cc := range msg.Cc {
		allTos += cc.String()
		if i < len(msg.Cc)-1 {
			allTos += ", "
		}
	}
	for i, bcc := range msg.Bcc {
		allTos += bcc.String()
		if i < len(msg.Bcc)-1 {
			allTos += ", "
		}

	}
	// First part: Human-readable explanation of the complaint
	textPartHeader := make(textproto.MIMEHeader)
	textPartHeader.Set("Content-Type", "text/plain; charset=\"utf-8\"")
	textPart, _ := writer.CreatePart(textPartHeader)
	fmt.Fprintln(textPart, fmt.Sprintf("This message is to inform you that a complaint was received for an email sent to %s.\n\n"+
		"Reason for complaint:\n"+
		"%s\n", allTos, complaintReason))

	// Second part: Machine-readable complaint feedback report
	feedbackPartHeader := make(textproto.MIMEHeader)
	feedbackPartHeader.Set("Content-Type", "message/feedback-report")
	feedbackPart, _ := writer.CreatePart(feedbackPartHeader)
	originalRecipients := ""
	for _, to := range msg.To {
		originalRecipients += "Original-Rcpt-To: " + to.String() + "\n"
	}
	reportedDomain := strings.Split(msg.From.Address, "@")[1]
	machineReadyReport := fmt.Sprintf(
		"Feedback-Type: %s\n"+
			"User-Agent: %s\n"+
			"Version: 1\n"+
			"Original-Mail-From: %s\n"+
			"%s"+
			"Arrival-Date: %s\n"+
			"Reported-Domain: %s\n",
		complaintReason,
		host,
		msg.From.String(),
		originalRecipients,
		time.UnixMilli(msg.Timestamp).Format(time.RFC1123Z),
		reportedDomain)
	fmt.Fprintln(feedbackPart, machineReadyReport)

	// add original message
	originalPartHeader := make(textproto.MIMEHeader)
	originalPartHeader.Set("Content-Type", "message/rfc822")
	originalPart, _ := writer.CreatePart(originalPartHeader)
	fmt.Fprintf(originalPart, "%s", originalMsgMime)

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

// Parsing raw mime message into a Mailio structure
func ParseMime(mime []byte) (*mailiosmtp.Mail, error) {
	msg, err := enmime.ReadEnvelope(bytes.NewReader(mime))
	if err != nil {
		return nil, err
	}

	email := &mailiosmtp.Mail{}

	// get the headers
	headers := msg.Root.Header
	email.MessageId = msg.GetHeader("Message-ID")
	from, fErr := mail.ParseAddress(headers.Get("From"))
	to, tErr := mail.ParseAddressList(headers.Get("To"))
	joinedErr := errors.Join(fErr, tErr)
	if joinedErr != nil {
		return nil, joinedErr
	}

	if headers.Get("Cc") != "" {
		cc, _ := mail.ParseAddressList(headers.Get("Cc"))
		if len(cc) > 0 {
			email.Cc = make([]mail.Address, len(cc))
			for i, addrPtr := range cc {
				email.Cc[i] = *addrPtr // Dereference the pointer to get the value
			}
		}
	}
	if headers.Get("Bcc") != "" {
		bcc, _ := mail.ParseAddressList(headers.Get("Bcc"))
		if len(bcc) > 0 {
			email.Bcc = make([]mail.Address, len(bcc))
			for i, addrPtr := range bcc {
				email.Bcc[i] = *addrPtr // Dereference the pointer to get the value
			}
		}
	}

	email.From = *from
	if len(to) > 0 {
		email.To = make([]mail.Address, len(to))
		for i, addrPtr := range to {
			email.To[i] = *addrPtr // Dereference the pointer to get the value
		}
	}

	// allHeaders := msg.RawHeaders()
	email.Headers = make(map[string][]string, 0)
	for key, value := range headers {
		vals := []string{}
		for _, v := range value {
			v = strings.ReplaceAll(v, "\n", "")
			v = strings.Trim(v, " ")
			vals = append(vals, v)
		}
		email.Headers[key] = vals
	}

	// get the body
	email.Subject = msg.GetHeader("Subject")
	dt, tErr := msg.Date()
	if tErr != nil {
		email.Timestamp = time.Now().UTC().UnixMilli()
	} else {
		email.Timestamp = dt.UnixMilli()
	}

	// mime.Attachments contains the non-inline attachments. (standard email attachments)
	var attachments []*mailiosmtp.SmtpAttachment
	if len(msg.Attachments) > 0 {
		for _, attachment := range msg.Attachments {
			attachments = append(attachments, &mailiosmtp.SmtpAttachment{
				ContentType: attachment.ContentType,
				Filename:    attachment.FileName,
				Content:     attachment.Content,
				ContentID:   attachment.ContentID,
			})
		}
	}
	if len(attachments) > 0 {
		email.Attachments = attachments
	}

	// body (plain, html, html cleaned)
	email.BodyHTML = msg.HTML
	email.BodyText = msg.Text
	email.BodyHTMLWithoutUnsafeTags = removeUnwantedTags(email.BodyHTML)

	// mime.Inlines is a slice of inlined attacments. These are typically images that are embedded in the HTML body
	for _, inline := range msg.Inlines {
		email.BodyRawPart = append(email.BodyRawPart, &mailiosmtp.MailBodyRaw{
			ContentType:        inline.ContentType,
			Content:            inline.Content,
			ContentDisposition: inline.Disposition,
			ContentID:          inline.ContentID,
		})
	}

	return email, nil
}

func removeUnwantedTags(html string) string {
	sanitizer := bluemonday.UGCPolicy()

	// Allow only a subset of HTML elements
	allowedElements := []string{"a", "abbr", "acronym", "address", "area", "b", "bdo", "big", "blockquote", "br", "button", "caption", "center", "cite", "code", "col", "colgroup", "dd", "del", "dfn", "dir", "div", "dl", "dt", "em", "fieldset", "font", "form", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "img", "input", "ins", "kbd", "label", "legend", "li", "map", "menu", "ol", "optgroup", "option", "p", "pre", "q", "s", "samp", "select", "small", "span", "strike", "strong", "sub", "sup", "table", "tbody", "td", "textarea", "tfoot", "th", "thead", "u", "tr", "tt", "u", "ul", "var"}
	sanitizer.AllowElements(allowedElements...)

	allowedStyles := []string{"azimuth", "background", "background-blend-mode", "background-clip", "background-color", "background-image", "background-origin", "background-position", "background-repeat", "background-size", "border", "border-bottom", "border-bottom-color", "border-bottom-left-radius", "border-bottom-right-radius", "border-bottom-style", "border-bottom-width", "border-collapse", "border-color", "border-left", "border-left-color", "border-left-style", "border-left-width", "border-radius", "border-right", "border-right-color", "border-right-style", "border-right-width", "border-spacing", "border-style", "border-top", "border-top-color", "border-top-left-radius", "border-top-right-radius", "border-top-style", "border-top-width", "border-width", "box-sizing", "break-after", "break-before", "break-inside", "caption-side", "clear", "color", "column-count", "column-fill", "column-gap", "column-rule", "column-rule-color", "column-rule-style", "column-rule-width", "column-span", "column-width", "columns", "direction", "display", "elevation", "empty-cells", "float", "font", "font-family", "font-feature-settings", "font-kerning", "font-size", "font-size-adjust", "font-stretch", "font-style", "font-synthesis", "font-variant", "font-variant-alternates", "font-variant-caps", "font-variant-east-asian", "font-variant-ligatures", "font-variant-numeric", "font-weight", "height", "image-orientation", "image-resolution", "isolation", "letter-spacing", "line-height", "list-style", "list-style-position", "list-style-type", "margin", "margin-bottom", "margin-left", "margin-right", "margin-top", "max-height", "max-width", "min-height", "min-width", "mix-blend-mode", "object-fit", "object-position", "opacity", "outline", "outline-color", "outline-style", "outline-width", "overflow", "padding", "padding-bottom", "padding-left", "padding-right", "padding-top", "pause", "pause-after", "pause-before", "pitch", "pitch-range", "quotes", "richness", "speak", "speak-header", "speak-numeral", "speak-punctuation", "speech-rate", "stress", "table-layout", "text-align", "text-combine-upright", "text-decoration", "text-decoration-color", "text-decoration-line", "text-decoration-skip", "text-decoration-style", "text-emphasis", "text-emphasis-color", "text-emphasis-style", "text-indent", "text-orientation", "text-overflow", "text-transform", "text-underline-position", "unicode-bidi", "vertical-align", "voice-family", "width", "word-spacing", "writing-mode"}
	sanitizer.AllowStyles(allowedStyles...)

	cleanHtml := sanitizer.Sanitize(html)

	return cleanHtml
}
