package util

import (
	"fmt"
	"strings"

	"github.com/mailio/go-mailio-did/did"
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

	messagingPath := global.Conf.Mailio.ServerDomain + global.Conf.Mailio.MessagingPath
	authPath := global.Conf.Mailio.ServerDomain + global.Conf.Mailio.AuthenticationPath
	didDoc, err := mailiodid.NewMailioDIDDocument(mkMailio, global.PublicKey, authPath, messagingPath)
	return didDoc, err
}

// Extracts the message endpoint from DID document
// in case localhost/127.0.0.1 schema is http, otherwise default schema is https
func ExtractDIDMessageEndpoint(didDoc *did.Document) string {
	// find a service endpoint for a recipient from DID Document
	endpoint := ""
	for _, service := range didDoc.Service {
		if service.Type == "DIDCommMessaging" {
			endpoint = strings.TrimSuffix(service.ServiceEndpoint, "/")
			scheme := "https"
			if !strings.HasPrefix(endpoint, "http") {
				if strings.Contains(endpoint, "localhost") || strings.Contains(endpoint, "127.0.0.1") {
					scheme = "http"
				}
				endpoint = fmt.Sprintf("%s://%s", scheme, endpoint)
			}
			break
		}
	}
	return endpoint
}
