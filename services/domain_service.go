package services

import (
	"context"
	"time"

	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
)

type DomainService struct {
	domainRepo repository.Repository
	env        *types.Environment
}

func NewDomainService(dbSelector repository.DBSelector, environment *types.Environment) *DomainService {
	domainRepo, err := dbSelector.ChooseDB(repository.Domain)
	if err != nil {
		panic(err)
	}
	return &DomainService{domainRepo: domainRepo, env: environment}
}

// Save a domain into a database (where name is the key)
func (s *DomainService) Save(domain *types.Domain) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	domain.Timestamp = time.Now().UnixMilli()
	err := s.domainRepo.Save(ctx, domain.Name, domain)
	if err != nil {
		return err
	}
	return nil
}

// Get domain by name (where name is the key)
func (s *DomainService) GetDomainByName(domainName string) (*types.Domain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	domain, err := s.domainRepo.GetByID(ctx, domainName)
	if err != nil {
		return nil, err
	}
	return domain.(*types.Domain), nil
}
