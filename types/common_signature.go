package types

type CommonSignature struct {
	SignatureBase64   string `json:"signatureBase64" validate:"required,base64"`
	CborPayloadBase64 string `json:"cborPayloadBase64" validate:"required,base64"`
	SenderDomain      string `json:"senderDomain" validate:"required"` // origin of the request (where DNS is published with Mailio public key)
}
