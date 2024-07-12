# Mailio Server

Mailio Server implementation based on [Mailio MIRs](https://mirs.mail.io) specifications. 

## Install

### Configuration

2. <a name="conf"></a>Create `conf.yaml` file with contents:

```yml
version: 1.0
scheme: http # http or https
port: 8080
title: Mailio Server
description: Mailio Server implementation based on mirs.mail.io specification
swagger: true
mode: release # "debug": or "release"

mailio:
  diskSpace: 524288000 # initial maximum disk size in bytes (500 MB)
  authenticationPath: /api/v1/didauth # don't change unless you know what you're doing
  messagingPath: /api/v1/mtp/message # don't change unless you know what you're doing
  emailSaltHex: abcdefgh # 8 bytes hex (abcdefgh)
  serverKeysPath: test_server_keys.json
  readVsReceived: 30 # 30% read makes a message go to goodreads, less to other
  serverDomain: mio.example.com # where this server is located on the internet
  serverSubdomainQueryList: # standard subdomains for the mail server. e.g. mio.example.com, mailio.example.com, ...
    - prefix: mio
    - prefix: mailio
    - prefix: didcomm
  serverHandshake:
    id: "mail_io_server_handshake" # guessable id
    type: 3 # 3 - server specific, 1 = personal, 2 = signup
    minimumLevel: 1 # reCaptchaV3
    subtypes:
      - subtype: 1
        frequencyMinutes: 0 # 0 - no limit
      - subtype: 2 # product updates
        frequencyMinutes: 43800 # 30 days
      - subtype: 3 # security updates
        frequencyMinutes: 0
      - subtype: 4 # promotional updates
        frequencyMinutes: 43800 # 30 days
      - subtype: 5
        frequencyMinutes: 43800 # 30 days
      - subtype: 6
        frequencyMinutes: 43800 # 30 days
  domains:
    - domain: example.io # e.g. example.com
    - domain: example.com # e.g. otherdomain.com

couchdb:
  host: localhost
  port: 5984
  scheme: http
  username: admin
  password: YOURPASSWORD

redis:
  host: localhost
  port: 6379
  username: default
  password: YOURPASSWORD

queue:
  concurrency: 50

prometheus:
  enabled: true
  username: prometheus
  password: YOURPASSWORD

# currently only mailgun supported
# check docs to implement: https://github.com/mailio/go-mailio-mailgun-smtp-handler
smtpservers:
  - provider: mailgun
    webhookurl: /webhook/mailgun_mime
    webhookkey: a55...
    domains:
    - domain: example.com
      sendapikey: 78...
    - domain: otherexample.com
      sendapikey: 674...

storage:
  type: s3
  key: ATR...
  secret: D+...
  bucket: mailio-bucket
  region: us-east-1
  
diskusagehandlers:
  - provider: aws
    path: mailio-attachments/mailio-attachments/user-attachment-inventory

```

### Mailio Server Configuration Explained

Ensure all passwords, keys, and sensitive information are correctly set in a secure manner.

For production, `change the scheme to https` and update the host and `serverDomain` to your actual domain.

The **serverSubdomainQueryList** is a list of potential third-party subdomains that our server will search for when communicating using the DIDComm protocol. This setting ensures that communication remains functional even if your `serverDomain` is a subdomain rather than the root domain.

For instance, if your `serverDomain` is `mio.example.com` instead of `example.com`, and people are sharing only their email addresses (as they commonly do), the communication will still work seamlessly.

**Example scenario**

- DID (Decentralized Identifier): did:web:mio.example.com:0x606d2...
- Email Address: myemail@example.com

In this example:

- The DID uses the subdomain mio.example.com. This is our servers domain.
- The email addresses, however, are associated with the root domain example.com.

By including `mio.example.com` in the `serverSubdomainQueryList`, our server can correctly interpret and route communications, when requesting remote DID documents, ensuring that messages sent to `myemail@example.com` can be processed using the DID `did:web:mio.example.com:0x606d2...`

This setting is crucial for maintaining compatibility and functionality in scenarios where subdomains are used for DIDs, while emails are tied to the root domain.

### Single node

```
git clone https://github.com/mailio/go-mailio-server.git
```

Create configuration file [`conf.yaml` in the root folder](#conf)

```
docker-compose up -d
```

### Multi-node

TDB (Kubernetes) or Helm chart maybe


## Development

1. Clone this repository
2. Create `conf.yaml` file
3. `swag init --parseDependency=true` to re-create swagger documentation
4. `go run environment.go main.go` to run the app


### Adding SMTP handler implementation

#### Overview

The application supports the integration of multiple SMTP service providers through a plugin interface. This interface allows for the seamless addition of new email service providers as needed, without requiring significant changes to the application's core functionality. The current implementation includes support for Mailgun, with the architecture designed to easily accommodate additional providers.

#### Configuration

The SMTP handler configuration is driven by the application's global configuration, typically defined in a configuration file (`cony.yaml`). Each SMTP provider's settings, such as API keys and domain information, are specified within this configuration file under the `MailWebhooks` section.

```yml
mailwebhooks:
  - provider: mailgun
    domain: sndmail.example.com
    sendapikey: sendapikey
    webhookurl: /webhook/mailgun_mime
    webhookkey: webhookkey
```

#### Adding a Custom SMTP Handler

##### 1. Implement the SMTP Handler Interface

Implement the SMTP handler interface, ensuring that it satisfies any required methods:

```go
type SmtpHandler interface {
	// ReceiveMail is a method called on the specific ESP handler webhook implementation
	ReceiveMail(request http.Request) (*mailiosmtp.Mail, error)
	// SendMimeMail returns generated message id or error
	SendMimeMail(mime []byte, to []mail.Address) (string, error)
}
```

Example implementation [here](https://github.com/mailio/go-mailio-mailgun-smtp-handler)

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

#### 2. Register the SMTP handler

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

##### 3. Update configuration

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
