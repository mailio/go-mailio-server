package services

import (
	"context"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
)

type WebAuthnService struct {
	env              *types.Environment
	webauthnUserRepo repository.Repository
}

func NewWebAuthnService(repoSelector *repository.CouchDBSelector, env *types.Environment) *WebAuthnService {
	if repoSelector == nil {
		panic("repoSelector cannot be nil")
	}
	webauthnUserRepo, rErr := repoSelector.ChooseDB(repository.WebAuthnUser)
	if rErr != nil {
		global.Logger.Log("msg", "failed to choose webauthn user repository", "error", rErr)
		panic(rErr)
	}
	return &WebAuthnService{
		webauthnUserRepo: webauthnUserRepo,
		env:              env,
	}
}

// GetUser gets a user from the database
func (s *WebAuthnService) GetUser(address string) (*types.WebAuhnUser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	resp, err := s.webauthnUserRepo.GetByID(ctx, address)
	if err != nil {
		if err != types.ErrNotFound {
			global.Logger.Log("msg", "failed to get user", "error", err)
		}
		return nil, err
	}

	var user types.WebAuthnUserDB
	mErr := repository.MapToObject(resp, &user)
	if mErr != nil {
		global.Logger.Log("msg", "failed to map object", "error", mErr)
		return nil, mErr
	}

	return types.MapWebAuthnUserFromDB(user), nil
}

// SaveUser saves a new user to the database or overrides existing user
func (s *WebAuthnService) SaveUser(user *types.WebAuhnUser) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	newUserDB := types.MapWebAuthnUserToDB(*user)

	resp, uErr := s.webauthnUserRepo.GetByID(ctx, newUserDB.Address)
	if uErr != nil {
		if uErr != types.ErrNotFound {
			global.Logger.Log("msg", "failed to get user", "error", uErr)
			return uErr
		}
	}

	if uErr != nil && resp != nil { // notFoundError
		var existing types.WebAuthnUserDB
		mErr := repository.MapToObject(resp.(*resty.Response), &existing)
		if mErr != nil {
			global.Logger.Log("msg", "failed to map object", "error", mErr)
			return mErr
		}
		newUserDB.ID = existing.ID
		newUserDB.Rev = existing.Rev
	}

	err := s.webauthnUserRepo.Save(ctx, newUserDB.Address, newUserDB)
	if err != nil {
		global.Logger.Log("msg", "failed to save user", "error", err)
		return err
	}
	return nil
}
