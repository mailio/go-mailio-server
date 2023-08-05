package types

import "github.com/mailio/go-mailio-core/models"

type Handshake struct {
	BaseDocument      `json:",inline"`
	Content           models.Handshake `json:"content"`
	SignatureBase64   string           `json:"signature"`
	CborPayloadBase64 string           `json:"cborPayload"`
}
