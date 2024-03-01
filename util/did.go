package util

import (
	mailiodid "github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/global"
)

// TODO! rename the CreateMailioDIDDocument (although it's functionality is ok, but the name is a bit misleading)
// CreateMailioDIDDocument creates a new mailio DID document (server DID)
func CreateMailioDIDDocument() (*mailiodid.Document, error) {
	mkMailio := &mailiodid.MailioKey{
		MasterSignKey: &mailiodid.Key{
			Type:      mailiodid.KeyTypeEd25519,
			PublicKey: global.PublicKey,
		},
	}

	messagingPath := global.Conf.Mailio.Domain + global.Conf.Mailio.MessagingPath
	authPath := global.Conf.Mailio.Domain + global.Conf.Mailio.AuthenticationPath
	didDoc, err := mailiodid.NewMailioDIDDocument(mkMailio, global.PublicKey, authPath, messagingPath)
	return didDoc, err
}
