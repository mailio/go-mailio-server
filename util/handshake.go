package util

import (
	"github.com/mailio/go-mailio-core/models"
	"github.com/mailio/go-mailio-server/types"
)

// Converting StoredHandshake to Handshake (user doesn't need details of revisions for now)
func StoredHandshakeToModelHandsake(storedHandshake *types.StoredHandshake) *models.Handshake {
	output := &models.Handshake{
		Content:           storedHandshake.Content,
		SignatureBase64:   storedHandshake.SignatureBase64,
		CborPayloadBase64: storedHandshake.CborPayloadBase64,
	}
	return output
}
