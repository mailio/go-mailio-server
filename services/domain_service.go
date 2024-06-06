package services

import (
	"context"
	"time"

	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
)

type DomainService struct {
	domainRepo repository.Repository
}

func NewDomainService(dbSelector *repository.CouchDBSelector) *DomainService {
	domainRepo, err := dbSelector.ChooseDB(repository.Domain)
	if err != nil {
		panic(err)
	}
	return &DomainService{
		domainRepo: domainRepo,
	}
}

// GetDomain retrieves domain information by domain name (e.g., example.com).
//
// The method performs the following steps:
// 1. Checks the local database for the domain. If found, it returns the domain.
// 2. If not found in the local database, it performs an MX record lookup:
//   - If MX records are found, the domain is stored in the database and returned.
//   - If MX records are not found, it proceeds to check if the domain is a Mailio server:
//   - The check includes querying a list of subdomain prefixes.
//   - If confirmed as a Mailio server, the domain is stored in the database and returned.
//
// Returns an error if the domain cannot be found or stored.
func (ds *DomainService) GetDomain(domain string) (*types.Domain, error) {
	// get domain from database
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	response, err := ds.domainRepo.GetByID(ctx, domain)
	if err != nil {
		return nil, err
	}
	var domainObj types.Domain
	mErr := repository.MapToObject(response, &domainObj)
	if mErr != nil {
		return nil, mErr
	}

	return &domainObj, nil
}

func (ds *DomainService) ResolveDomain(domain string) (*types.Domain, error) {
	//TODO! chanfge to false (so it doesn't force it)
	resolvedDomain, rdErr := resolveDomain(ds.domainRepo, domain, true)
	if rdErr != nil {
		return nil, rdErr
	}

	return resolvedDomain, nil
}
