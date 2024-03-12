package types

var DENIED_EXTENSIONS = map[string]string{"ade": "ade", "adp": "adp", "apk": "apk", "appx": "appx", "appxbundle": "appxbundle", "bat": "bat", "cab": "cab", "chm": "chm", "cmd": "cmd", "com": "com", "cpl": "cpl", "dll": "dll", "dmg": "dmg", "ex": "ex", "ex_": "ex_", "exe": "exe", "hta": "hta", "ins": "ins", "isp": "isp", "iso": "iso", "jar": "jar", "js": "js", "jse": "jse", "lib": "lib", "lnk": "lnk", "mde": "mde", "msc": "msc", "msi": "msi", "msix": "msix", "msixbundle": "msixbundle", "msp": "msp", "mst": "mst", "nsh": "nsh", "pif": "pif", "ps1": "ps1", "scr": "scr", "sct": "sct", "shb": "shb", "sys": "sys", "vb": "vb", "vbe": "vbe", "vbs": "vbs", "vxd": "vxd", "wsc": "wsc", "wsf": "wsf", "wsh": "wsh"}

var (
	DIDCommIntentMessage   = "message"   // ordinary message
	DIDCommIntentHandshake = "handshake" // handshake message
	DIDCommIntentDelivery  = "delivery"  // delivery message (acknowledgement, failure, etc.)

	MailioFolderInbox     = "inbox"
	MailioFolderGoodReads = "goodreads"
	MailioFolderOther     = "other"
	MailioFolderSent      = "sent"
	MailioFolderDraft     = "draft"
	MailioFolderArchive   = "archive"
	MaolioFolderTrash     = "trash"
	MailioFolderSpam      = "spam"
	MailioFolderHandshake = "handshake"
)

// MailioMessage is a struct that is meant to be stored in the database
type MailioMessage struct {
	BaseDocument   `json:",inline"`
	ID             string          `json:"id" validate:"required"`   // globally unique message identifier UUID (RFC 4122) recommended
	From           string          `json:"from" validate:"required"` // either the sender's DID or the sender's email address
	DIDCommMessage *DIDCommMessage `json:"didCommMessage,omitempty"` // the DIDComm message
	// SmtpMessage    *SMTPMessage     `json:"smtpMessage,omitempty"`       // the SMTP message
	Folder      string `json:"folder" validate:"required"`  // the folder where the message is stored
	Created     int64  `json:"created" validate:"required"` // time of message creation in UTC milliseconds since epoch
	Modified    int64  `json:"modified,omitempty"`          // time of message modification in UTC milliseconds since epoch
	IsAutomated bool   `json:"isAutomated,omitempty"`       // true if the message is automated
	IsForwarded bool   `json:"isForwarded,omitempty"`       // true if the message is forwarded
	IsReplied   bool   `json:"isReplied,omitempty"`         // true if the message is replied
	IsRead      bool   `json:"isRead,omitempty"`            // true if the message is read
}

type DIDCommMessage struct {
	Type                 string                 `json:"type" validate:"required,oneof=application/didcomm-encrypted+json application/didcomm-signed+json"` // a valid message type URI (MUST be: application/didcomm-encrypted+json or application/didcomm-signed+json)
	ID                   string                 `json:"id" validate:"required"`                                                                            // globally unique message identifier UUID (RFC 4122) recommended
	From                 string                 `json:"from" validate:"required"`                                                                          // sender DID required because all mailio messages are encrypted
	To                   []string               `json:"to" validate:"required,min=1"`                                                                      // in format: did:web:mail.io:0xabc -> recipient DIDs
	Thid                 string                 `json:"thid,omitempty"`                                                                                    // thread identifier. Uniquely identifies the thread that the message belongs to. If not included, the id property of the message MUST be treated as the value of the thid.
	Pthid                string                 `json:"pthid,omitempty"`                                                                                   // parent thread identifier. Uniquely identifies the parent thread that the message belongs to. If not included, the message is the first message in the thread.
	ExpiresTime          int64                  `json:"expiresTime,omitempty"`                                                                             // sender will abort the protocol if it doesn't get a response by this time (UTC milliseconds since epoch)
	CreatedTime          int64                  `json:"createdTime,omitempty"`                                                                             // time of message creation in UTC milliseconds since epoch
	Next                 string                 `json:"next,omitempty"`                                                                                    // in case forward message
	FromPrior            string                 `json:"fromPrior,omitempty"`                                                                               // A DID is rotated by sending a message of any type to the recipient to be notified of the rotation
	Intent               string                 `json:"intent,omitempty" validate:"omitempty,oneof=message handshake delivery"`                            // the intent of the message (if empty, ordinary message
	EncryptedBody        *EncryptedBody         `json:"body,omitempty"`                                                                                    // the body attribute contains all the data and structure defined uniquely for the schema associated with the type attribute. It MUST be a JSON object conforming to RFC 7159                              // the encrypted message body
	PlainBodyBase64      string                 `json:"plainBodyBase64,omitempty" validate:"omitempty,base64"`                                             // the plain text message body, base64 encoded (optional)
	EncryptedAttachments []*EncryptedAttachment `json:"attachments,omitempty"`                                                                             // attachments to the message                                                // MTP status message
}

type DIDCommRequest struct {
	SignatureScheme string          `json:"signatureScheme" validate:"required,oneof=EdDSA_X25519"`
	Timestamp       int64           `json:"timestamp" validate:"required"`
	DIDCommMessage  *DIDCommMessage `json:"didCommMessage" validate:"required"`
}

// DIDCommSignedMessage is a struct that represents a signed message according to JWS standard with CBOR payload
type DIDCommSignedRequest struct {
	DIDCommRequest    *DIDCommRequest `json:"didCommRequest" validate:"required"`
	CborPayloadBase64 string          `json:"cborPayloadBase64" validate:"required,base64"` // the payload that was signed, which is base64 encoded.
	SignatureBase64   string          `json:"signatureBase64" validate:"required,base64"`   // the signature of the payload, which is base64 encoded.
	SenderDomain      string          `json:"senderDomain" validate:"required"`             // origin of the request (where DNS is published with Mailio public key)
}

// EncryptedMailioBody is a struct that represents an encrypted message according to JWE standard
type EncryptedBody struct {
	Ciphertext string      `json:"ciphertext" validate:"required"`       // the encrypted message
	IV         string      `json:"iv" validate:"required"`               // the initialization vector (nonce)
	Recipients []Recipient `json:"recipients" validate:"required,min=1"` // the recipients of the message (at least one)
	Tag        string      `json:"tag" validate:"required"`              // integrity check on the encrypted message
	Protected  string      `json:"protected" validate:"required"`        // the protected header
	Signature  Signature   `json:"signature" validate:"required"`        // JWS digital signature
}

// Delivery message (successfull or failed)
type PlainBodyDelivery struct {
	StatusCodes []*MTPStatusCode `json:"statusCodes" validate:"required,min=1"` // MTP status messages
}

// EncryptedMailioAttachment is a struct that represents an encrypted attachment according to JWE standard
type EncryptedAttachment struct {
	ID          string                   `json:"id" validate:"required"`                                              // a globally unique identifier for the attachment
	Description string                   `json:"description,omitempty"`                                               // a human-readable description of the attachment (optional)
	MediaType   string                   `json:"mediaType" validate:"required,eq=application/didcomm-encrypted+json"` // the media type of the attachment
	Data        *EncryptedAttachmentData `json:"data" validate:"required"`                                            // the encrypted message body
}

// EncryptedAttachmentData JWE encrypted attachment data
type EncryptedAttachmentData struct {
	Json *EncryptedBody `json:"json" validate:"required"`
}

// Recipient is a struct that represents a recipient of an encrypted message
type Recipient struct {
	EncryptedKey string `json:"encrypted_key" validate:"required"` // Tthe key used to encrypt the ciphertext, encrypted with the recipient's public key
	Header       Header `json:"header" validate:"required"`        // encryption parameters specific to each recipient
}

type Header struct {
	Kid string `json:"kid" validate:"required"` //  (Key ID): A hint indicating which key was used to encrypt the
	Epk Epk    `json:"epk" validate:"required"` // (Ephemeral Public Key): A temporary public key that was used in conjunction with the recipient's public key to encrypt the encrypted_key
}

// Ephemeral Public Key
type Epk struct {
	X   string `json:"x" validate:"required"`   // The X coordinate for the elliptic curve point
	Crv string `json:"crv" validate:"required"` // The curve parameter used for the key
	Kty string `json:"kty" validate:"required"` // Key Type, indicating the type of key used, such as an elliptic curve key ("OKP" for Octet Key Pair).
}

type Signature struct {
	Signatures []SignatureDetail `json:"signatures"`
	Payload    string            `json:"payload"` // The payload that was signed, which is base64URL encoded.
}

type SignatureDetail struct {
	Signature string `json:"signature"`
	Protected string `json:"protected"` // Base64URL encoded JSON string containing the header parameters used for the signature
}
