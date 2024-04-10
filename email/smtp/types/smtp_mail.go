package mailiosmtp

import "net/mail"

const (
	// VerdictStatusPass is the verdict status for PASS
	VerdictStatusPass = "PASS"
	// VerdictStatusFail is the verdict status for FAIL
	VerdictStatusFail = "FAIL"
	// VerdictStatusNotAvailable is the verdict status for NOT_AVAILABLE
	VerdictStatusNotAvailable = "NOT_AVAILABLE"
)

type VerdictStatus struct {
	Status string `json:"status" validate:"required,oneof=PASS FAIL NOT_AVAILABLE"` // possible values: PASS, FAIL, NOT_AVAILABLE
}

type Mail struct {
	From                      mail.Address        `json:"from"`              // The email address of the original sender.
	ReplyTo                   []*mail.Address     `json:"replyTo,omitempty"` // The email address to which bounces (undeliverable notifications) are to be forwarded.
	To                        []mail.Address      `json:"to"`                // The email addresses of the recipients.
	Cc                        []*mail.Address     `json:"cc,omitempty"`      // The email addresses of the CC recipients.
	Bcc                       []*mail.Address     `json:"bcc,omitempty"`     // The email addresses of the BCC recipients.
	MessageId                 string              `json:"messageId"`         // message id
	Subject                   string              `json:"subject"`
	BodyText                  string              `json:"bodyText,omitempty"`                  // The text version of the email.
	BodyHTML                  string              `json:"bodyHtml,omitempty"`                  // The HTML version of the email.
	BodyHTMLWithoutUnsafeTags string              `json:"bodyHTMLWithoutUnsafeTags,omitempty"` // The HTML version of the email with removed unsafe tags
	BodyInlinePart            []*MailBodyRaw      `json:"bodyInlinePart,omitempty"`            // The raw inline content of the email.
	Headers                   map[string][]string `json:"headers,omitempty"`                   // The email headers. (one header can be specified multiple times with different values)
	Attachments               []*SmtpAttachment   `json:"attachments,omitempty"`
	SizeBytes                 int64               `json:"sizeBytes"`              // The size of the email in bytes.
	SizeHtmlBodyBytes         int64               `json:"sizeHtmlBodyBytes"`      // The size of the HTML body in bytes.
	SizeInlineBytes           int64               `json:"sizeInlineBytes"`        // The size of the inline content in bytes.
	SizeAttachmentsBytes      int64               `json:"sizeAttachmentsBytes"`   // The size of the attachments in bytes.
	Timestamp                 int64               `json:"timestamp"`              // since epoch in miliseconds
	SpamVerdict               *VerdictStatus      `json:"spamVerdict,omitempty"`  // optional, spam verdict
	VirusVerdict              *VerdictStatus      `json:"virusVerdict,omitempty"` // optional, virus verdict
	SpfVerdict                *VerdictStatus      `json:"spfVerdict,omitempty"`   // optinal, spf verdict
	DkimVerdict               *VerdictStatus      `json:"dkimVerdict,omitempty"`  // optional, dkim verdict
	DmarcVerdict              *VerdictStatus      `json:"dmarcVerdict"`           // optional, dmarc verdict
}

type MailBodyRaw struct {
	ContentID          string `json:"contentId,omitempty"`          // The content id of the raw email.
	ContentType        string `json:"contentType"`                  // The content type of the raw email.
	ContentDisposition string `json:"contentDisposition,omitempty"` // The content disposition of the raw email.
	Content            []byte `json:"content"`                      // The raw content of the email.
}

type SmtpAttachment struct {
	ContentType        string `json:"contentType"`                  // The content type of the attachment.
	ContentDisposition string `json:"contentDisposition,omitempty"` // The content disposition of the attachment.
	Filename           string `json:"filename"`                     // The name of the attachment.
	Content            []byte `json:"content"`                      // The content of the attachment.
	ContentID          string `json:"contentId,omitempty"`          // The content id of the attachment.
}

func (m *Mail) GetHeader(key string) string {
	if m.Headers == nil {
		return ""
	}
	if values, ok := m.Headers[key]; ok {
		return values[0]
	}
	return ""
}
