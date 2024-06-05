package util

import (
	mailiodid "github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
)

// TODO! rename the CreateMailioDIDDocument (although it's functionality is ok, but the name is a bit misleading)
// CreateMailioDIDDocument creates a new mailio DID document (server DID)
func CreateMailioDIDDocument(domain string) (*mailiodid.Document, error) {

	if _, ok := global.PublicKeyByDomain[domain]; !ok {
		return nil, types.ErrDomainNotFound
	}
	publicKey := global.PublicKeyByDomain[domain]

	mkMailio := &mailiodid.MailioKey{
		MasterSignKey: &mailiodid.Key{
			Type:      mailiodid.KeyTypeEd25519,
			PublicKey: publicKey,
		},
	}

	messagingPath := domain + global.Conf.Mailio.MessagingPath
	authPath := domain + global.Conf.Mailio.AuthenticationPath
	didDoc, err := mailiodid.NewMailioDIDDocument(mkMailio, publicKey, authPath, messagingPath)
	return didDoc, err
}
