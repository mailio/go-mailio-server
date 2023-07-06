package services

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-core/did"
	mailioErrors "github.com/mailio/go-mailio-core/errors"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
)

// UserMapping service is used
// - to map a user to a DID either using a DID resolver
type MailioDIDResolverService struct {
	repo        repository.Repository
	restyClient *resty.Client
}

func NewMailioDIDResolverService(repo repository.Repository) *MailioDIDResolverService {
	rc := resty.New()
	return &MailioDIDResolverService{
		repo:        repo,
		restyClient: rc,
	}
}

func (mdrs *MailioDIDResolverService) StoreUserDID(doc *did.Document) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	return mdrs.repo.Save(ctx, doc.ID.String(), doc)
}

// resolves a DID to a users DID document (on any mailio server)
// example of mailio DID:
// did:mailio:0xabcd1234 is equivalent to
// did:mailio:mail.io:0xabcd1234
func (mdrs *MailioDIDResolverService) ResolveDID(mailioDIDAddress string) (*did.Document, error) {
	parts := strings.Split(mailioDIDAddress, ":")
	if len(parts) < 3 || parts[0] != "did" || parts[1] != "mailio" {
		return nil, errors.New("invalid did")
	}
	domain := global.Conf.Mailio.Domain
	mailioAddress := ""
	if len(parts) == 3 {
		// this server
		mailioAddress = parts[2]
	} else if len(parts) == 4 {
		// possiby another server
		domain = parts[2]
		mailioAddress = parts[3]
	} else {
		return nil, errors.New("invalid did")
	}
	if mailioAddress == "" {
		return nil, errors.New("invalid did")
	}
	// local server
	if domain == global.Conf.Mailio.Domain {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()
		d := did.DIDKeyPrefix + ":" + mailioAddress
		didDoc, err := mdrs.repo.GetByID(ctx, d)
		if err != nil {
			// TODO: check if not found
			return nil, err
		}
		out := didDoc.(*did.Document)
		return out, nil
	}
	// remote server
	resp, err := mdrs.restyClient.R().
		Get("https://" + domain + "/api/v1/user/" + mailioAddress)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() == 200 {
		out := &did.Document{}
		err = json.Unmarshal(resp.Body(), &out)
		if err != nil {
			return nil, err
		}
		return out, nil
	}
	if resp.StatusCode() == 404 {
		return nil, mailioErrors.ErrNotFound
	}
	return nil, mailioErrors.ErrBadRequest
}
