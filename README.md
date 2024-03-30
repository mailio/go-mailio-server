# Mailio Server

Mailio Server implementation based on [Mailio MIRs](https://mirs.mail.io) specifications. 

## Development

1. Clone this repository
2. Create `conf.yaml` file with contents:

```yml
version: 1.0
port: 8080
host: localhost # custom domain, for development leave localhost
scheme: http # http or https
title: Mailio Server
description: Mailio Server implementation based on mirs.mail.io specification
swagger: true
mode: debug # "debug": or "release"

couchdb:
  host: localhost
  port: 5984
  scheme: http
  username: admin
  password: admin

awssmtp:
  username: test
  password: test
```
3. `swag init --parseDependency=true` to re-create documentation
4. `go run environment.go main.go` to run the app

## Adding SMTP handler implementation

### Overview

The application supports the integration of multiple SMTP service providers through a plugin interface. This interface allows for the seamless addition of new email service providers as needed, without requiring significant changes to the application's core functionality. The current implementation includes support for Mailgun, with the architecture designed to easily accommodate additional providers.

### Configuration

The SMTP handler configuration is driven by the application's global configuration, typically defined in a configuration file (`cony.yaml`). Each SMTP provider's settings, such as API keys and domain information, are specified within this configuration file under the `MailWebhooks` section.

```yml
mailwebhooks:
  - provider: mailgun
    domain: sndmail.example.com
    sendapikey: sendapikey
    webhookurl: /webhook/mailgun_mime
    webhookkey: webhookkey
```

### Adding a Custom SMTP Handler

#### 1. Implement the SMTP Handler Interface

Implement the SMTP handler interface, ensuring that it satisfies any required methods:

```go
type SmtpHandler interface {
	// ReceiveMail is a method called on the specific ESP handler webhook implementation
	ReceiveMail(request http.Request) (*mailiosmtp.Mail, error)
	// SendMimeMail returns generated message id or error
	SendMimeMail(mime []byte, to []mail.Address) (string, error)
}
```

You can find all helper functions [here](https://github.com/mailio/go-mailio-server/blob/main/email/smtp/mailio_smtp.go)

```go

// Parsing raw EML messages using enmime library: https://github.com/emime
func ParseMime(mime []byte) (*mailiosmtp.Mail, error)

// converts a message to a mime message preparing it for sending
func ToMime(msg *mailiosmtp.Mail, mailhost string) ([]byte, error) {

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
func ToBounce(recipient mail.Address, msg mailiosmtp.Mail, bounceCode string, bounceReason string, mailhost string) ([]byte, error)

// Collecting complaints. Report complaint to designated recipient (something like complaints@mail.io).
func ToComplaint(recipient mail.Address, reporter mail.Address, msg mailiosmtp.Mail, complaintReason string, mailhost string) ([]byte, error)
```

[api_mailreceive_webhook.go](https://github.com/mailio/go-mailio-server/blob/main/api/api_mailreceive_webhook.go#L19)
```go
// add your provider in th api_mailreceive_webhook.go registration loop. Example:
for _, wh := range global.Conf.MailWebhooks {
  if wh.Provider == "your-provider-name" {
    handler := yourprovider.NewYourProviderSmtpHandler(wh.APIKey, wh.OtherConfig)
    smtpmodule.RegisterSmtpHandler(wh.Provider, handler)
  }
}
```

Add your provider configuration under `conf.yaml` -> `mailwebhooks`:

```yml
mailwebhooks:
  - provider: mailgun
    domain: sndmail.example.com
    sendapikey: sendapikey
    webhookurl: /webhook/mailgun_mime
    webhookkey: webhookkey
  - provider: my-provider-name
    domain: my-provider-domain
    sendapikey: apikey
    webhookurl: /webhook/my-provider-webhook-url
    webhookkey: not-used
```
