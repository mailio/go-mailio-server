package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-kit/log/level"
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
		level.Error(global.Logger).Log("msg", "failed to choose webauthn user repository", "error", rErr)
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
			level.Error(global.Logger).Log("msg", "failed to get user", "error", err)
		}
		return nil, err
	}

	var user types.WebAuthnUserDB
	mErr := repository.MapToObject(resp, &user)
	if mErr != nil {
		level.Error(global.Logger).Log("msg", "failed to map object", "error", mErr)
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
			level.Error(global.Logger).Log("msg", "failed to get user", "error", uErr)
			return uErr
		}
	}

	if uErr != nil && resp != nil { // notFoundError
		var existing types.WebAuthnUserDB
		mErr := repository.MapToObject(resp.(*resty.Response), &existing)
		if mErr != nil {
			level.Error(global.Logger).Log("msg", "failed to map object", "error", mErr)
			return mErr
		}
		newUserDB.ID = existing.ID
		newUserDB.Rev = existing.Rev
	}

	err := s.webauthnUserRepo.Save(ctx, newUserDB.Address, newUserDB)
	if err != nil {
		level.Error(global.Logger).Log("msg", "failed to save user", "error", err)
		return err
	}
	return nil
}

/**
 * GetUserByEmail gets a user from the database by email (querying the field: name)
 */
func (s *WebAuthnService) GetUserByEmail(email string) (*types.WebAuthnUserDB, error) {
	email = strings.ToLower(email)
	client := s.webauthnUserRepo.GetClient().(*resty.Client).R().
		SetHeader("Accept", "application/json").
		SetHeader("Content-Type", "application/json").
		SetBody(map[string]interface{}{
			"selector": map[string]interface{}{
				"name": map[string]interface{}{
					"$eq": email,
				},
			},
			"limit": 1, // Assuming "limit" should be an integer
		})
	resp, err := client.Post(fmt.Sprintf("%s/_find", repository.WebAuthnUser))
	if err != nil {
		level.Error(global.Logger).Log("msg", "failed to get user by email", "error", err)
		return nil, err
	}
	if resp.Error() != nil {
		if resp.StatusCode() == 404 {
			return nil, types.ErrNotFound
		}
		level.Error(global.Logger).Log("msg", "failed to get user by email", "error", resp.Error())
		return nil, types.ErrInternal
	}

	if resp.StatusCode() != 200 {
		return nil, types.ErrInternal
	}
	var existing map[string]interface{}
	mErr := json.Unmarshal(resp.Body(), &existing)
	if mErr != nil {
		level.Error(global.Logger).Log("msg", "failed to map object", "error", mErr)
		return nil, mErr
	}
	// Ensure "docs" is a slice of interfaces and check if it's not empty
	docs, ok := existing["docs"].([]interface{})
	if !ok || len(docs) == 0 {
		return nil, types.ErrNotFound
	}
	// Convert the first element of "docs" to JSON for unmarshaling
	docBytes, err := json.Marshal(docs[0])
	if err != nil {
		level.Error(global.Logger).Log("msg", "failed to marshal document", "error", err)
		return nil, err
	}
	// Unmarshal the JSON into the WebAuthnUserDB struct
	var user types.WebAuthnUserDB
	if err := json.Unmarshal(docBytes, &user); err != nil {
		level.Error(global.Logger).Log("msg", "failed to unmarshal document into user", "error", err)
		return nil, err
	}

	return &user, nil
}
