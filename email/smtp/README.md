# Generic interface around receiving and sending email

The Email service can be AWS SES, Mailgun, Postal or any other. 

You can find example implementation using Mailgun's service [here](https://github.com/mailio/go-mailio-mailgun-smtp-handler)

The code inherits the same principle as datastore/sql pluggable interfaces. In this case this interface must be implemented by your custom SMTP handler: 

```go
type SmtpHandler interface {
	// ReceiveMail is a method called on the specific ESP handler webhook implementation
	ReceiveMail(request http.Request) (*types.Mail, error)
	// SendMimeMail returns generated message id or error
	SendMimeMail(mime []byte, to []mail.Address) (string, error)
}
```

Mailio Smtp also has a set of helper functions. 

## Helper functions

```go
// converting html/text into plain/text
htmlToText(myHtml)
```

```go
// generates RFC2822 compliant Message-ID
generateRFC2822MessageID()
```

```go
// ToMime converts a Mailio specific struct to email Mime message
ToMime(msg *types.Mail) ([]byte, error)

// ToBounce converts a Mailio specific struct to a RFC compliant bounce message
ToBounce(recipient mail.Address, msg types.Mail, bounceCode string, bounceReason string) ([]byte, error)

// ToComplaint converts a Mailio specific struct to a RFC compliant complaint message
ToComplaint(recipient mail.Address, reporter mail.Address, msg types.Mail, complaintReason string) ([]byte, error)

// ParseMime parses an email message and returns a Mailio specific struct
ParseMime(mime []byte) (*types.Mail, error)
```