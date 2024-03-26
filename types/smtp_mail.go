package types

import "net/mail"

type VerdictStatus struct {
	Status string `json:"status" validate:"required,oneof=PASS FAIL NOT_AVAILABLE"` // possible values: PASS, FAIL, NOT_AVAILABLE
}

// // Action, original source of data (file, ipfs, s3, ...)
// type Action struct {
// 	Type      string `json:"type,omitempty"`      // type of action
// 	Topic     string `json:"topic,omitempty"`     // topic ()
// 	ObjectURL string `json:"objectUrl,omitempty"` // original source of the message (ipfs/s3,...)
// }

// type CommonHeaders struct {
// 	From      []string `json:"from"`
// 	Timestamp int64    `json:"timestamp"` // epoch time in miliseconds
// 	To        []string `json:"to"`        // list of recipients (e.g. ["Jane Doe <jane@example.com>, Mary Doe <mary@example.com>, Richard Doe <richard@example.com>"])
// 	MessageID string   `json:"messageId"`
// 	Subject   string   `json:"subject,omitempty"`
// }

// // Mail is a mail
// type Mail struct {
// 	Source        string         `json:"source"`                  // sender
// 	Destination   []string       `json:"destination"`             // list of recipients
// 	CommonHeaders *CommonHeaders `json:"commonHeaders,omitempty"` // optional (if webhook provides it, otherwise parse from RawMime)
// 	MessageID     string         `json:"messageId,omitempty"`     // optional, unique id of the message (if webhook parses it, otherwise parse from RawMime)
// 	RawMime       []byte         `json:"rawMime,omitempty"`       // optional, raw mime messages
// }

// // Receipt is a receipt of a message
// type Receipt struct {
// 	ProcessingTimeMillis int            `json:"processingTimeMillis,omitempty"` // optional field, only present if the message was processed
// 	Recipients           []string       `json:"recipients" validate:"required"` // list of recipients
// 	SpamVerdict          *VerdictStatus `json:"spamVerdict,omitempty"`          // optional, spam verdict
// 	VirusVerdict         *VerdictStatus `json:"virusVerdict,omitempty"`         // optional, virus verdict
// 	SpfVerdict           *VerdictStatus `json:"spfVerdict,omitempty"`           // optinal, spf verdict
// 	DkimVerdict          *VerdictStatus `json:"dkimVerdict,omitempty"`          // optional, dkim verdict
// 	DmarcVerdict         *VerdictStatus `json:"dmarcVerdict"`                   // optional, dmarc verdict
// 	Action               *Action        `json:"action"`                         // optional, action
// }

// type BouncedRecipient struct {
// 	EmailAddress   string `json:"emailAddress" validate:"email,required"`
// 	Status         string `json:"status" vlaidate:"required"`
// 	Action         string `json:"action" validate:"required"` // failed
// 	DiagnosticCode string `json:"diagnosticCode"`
// }

// // optional field, only present if the message was a bounce
// // TODO!: https://docs.aws.amazon.com/ses/latest/dg/notification-contents.html#bounce-types
// type Bounce struct {
// 	BounceType        string              `json:"bounceType"`              // e.g. Permament
// 	BounceSubType     string              `json:"bounceSubType,omitempty"` // e.g. General
// 	ReportingMTA      string              `json:"reportingMTA,omitempty"`  // e.g. "dns; email.example.com", The value of the Reporting-MTA field from the DSN. This is the value of the MTA that attempted to perform the delivery, relay, or gateway operation described in the DSN.
// 	BouncedRecipients []*BouncedRecipient `json:"bouncedRecipients"`       //  e.g. {"emailAddress":"jane@example.com","status":"5.1.1","action":"failed","diagnosticCode":"smtp; 550 5.1.1 <jane@example.com>... User"}
// 	RemoteMtaIp       string              `json:"remoteMtaIp,omitempty"`   // e.g. 127.0.0.1" The IP address of the MTA to which Amazon SES attempted to deliver the email.
// }

// type ComplainedRecipient struct {
// 	EmailAddress string `json:"emailAddress" validate:"email,required"`
// }

// // optional field, only present if the message was a complaint
// type Complaint struct {
// 	UserAgent             string                 `json:"userAgent,omitempty"`             // e.g. AnyCompany Feedback Loop (V0.01)
// 	ComplainedRecipients  []*ComplainedRecipient `json:"complainedRecipients"`            // e.g. [{"emailAddress":"
// 	ComplaintFeedbackType string                 `json:"complaintFeedbackType,omitempty"` // e.g. abuse
// }

// // optional field, only present if the message was delivered (not necessary to use really)
// type Delivery struct {
// 	Timestamp            int64  `json:"timestamp"`            // miliseconds since epoch
// 	ProcessingTimeMillis int    `json:"processingTimeMillis"` // miliseconds
// 	SmtpResponse         string `json:"smtpResponse"`         // e.g. 250 ok:  Message 111 accepted
// 	ReportingMTA         string `json:"reportingMTA"`         // e.g. a8-70.smtp-out.mail.io
// 	RemoteMtaIp          string `json:"remoteMtaIp"`          // e.g. 127.0.2.0
// }

// // main object
// type MailReceived struct {
// 	NotificationType string     `json:"notificationType" validate:"required"` // possible values: Bounce, Complaint or Delivery
// 	Mail             *Mail      `json:"mail"`
// 	Receipt          *Receipt   `json:"receipt,omitempty"`
// 	Bounce           *Bounce    `json:"bounce,omitempty"`
// 	Complaint        *Complaint `json:"complaint,omitempty"`
// 	Delivery         *Delivery  `json:"delivery,omitempty"`
// 	Timestamp        int64      `json:"timestamp"` // since epoch in miliseconds
// }

type Mail struct {
	From                      mail.Address        `json:"from"`              // The email address of the original sender.
	ReplyTo                   []mail.Address      `json:"replyTo,omitempty"` // The email address to which bounces (undeliverable notifications) are to be forwarded.
	To                        []mail.Address      `json:"to"`                // The email addresses of the recipients.
	Cc                        []mail.Address      `json:"cc,omitempty"`      // The email addresses of the CC recipients.
	Bcc                       []mail.Address      `json:"bcc,omitempty"`     // The email addresses of the BCC recipients.
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
