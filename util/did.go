package util

import (
	mailiodid "github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/global"
)

// CreateMailioDIDDocument creates a new mailio DID document (server DID)
func CreateMailioDIDDocument() (*mailiodid.Document, error) {
	mkMailio := &mailiodid.MailioKey{
		MasterSignKey: &mailiodid.Key{
			Type:      mailiodid.KeyTypeEd25519,
			PublicKey: global.PublicKey,
		},
	}

	didDoc, err := mailiodid.NewMailioDIDDocument(mkMailio, global.PublicKey, global.Conf.Mailio.AuthenticationPath, global.Conf.Mailio.MessagingPath)
	return didDoc, err
}
