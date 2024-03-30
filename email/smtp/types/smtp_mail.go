package mailiosmtp

import "net/mail"

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
	BodyRawPart               []*MailBodyRaw      `json:"bodyRaw,omitempty"`                   // The raw content of the email.
	Headers                   map[string][]string `json:"headers,omitempty"`                   // The email headers. (one header can be specified multiple times with different values)
	Attachments               []*SmtpAttachment   `json:"attachments,omitempty"`
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
