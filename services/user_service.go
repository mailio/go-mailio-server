package services

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
)

type UserService struct {
	repoSelector *repository.CouchDBSelector
}

func NewUserService(repoSelector *repository.CouchDBSelector) *UserService {
	if repoSelector == nil {
		panic("repoSelector cannot be nil")
	}
	return &UserService{
		repoSelector: repoSelector,
	}
}

// CreateUser creates a new user with the given email and password.
// It returns a pointer to an InputEmailPassword struct and an error (if any).
func (us *UserService) CreateUser(user *types.User, databasePassword string) (*types.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userRepo, rErr := us.repoSelector.ChooseDB(repository.User)
	if rErr != nil {
		return nil, rErr
	}
	err := userRepo.Save(ctx, fmt.Sprintf("%s:%s", "org.couchdb.user", user.MailioAddress), map[string]interface{}{"name": user.MailioAddress, "password": databasePassword, "roles": []string{}, "type": "user", "encryptedEmail": user.EncryptedEmail, "created": user.Created})
	if err != nil {
		global.Logger.Log(err, "Failed to register user")
		return nil, err
	}

	hexUser := "userdb-" + hex.EncodeToString([]byte(user.MailioAddress)) // MailioAddress already hex

	// wait for database to be created
	c := userRepo.GetClient().(*resty.Client)

	for i := 1; i < 5; i++ {

		headResponse, hErr := c.R().Get(fmt.Sprintf("%s", hexUser))
		if hErr != nil {
			return nil, errors.New("Failed to create user database")
		}
		if headResponse.StatusCode() == 200 {
			break
		}

		if headResponse.StatusCode() == 404 {
			backoff := int(100 * math.Pow(2, float64(i)))
			time.Sleep(time.Duration(backoff) * time.Millisecond)
			continue
		} else {
			return nil, errors.New("Failed to create user database")
		}
	}

	iErr := repository.CreateUserDatabaseFolderCreatedIndex(userRepo, hexUser)
	if iErr != nil {
		return nil, iErr
	}

	return user, nil
}

// Maps encrypted email to mailio address so outside users can request per user email if they know it
func (us *UserService) MapEmailToMailioAddress(user *types.User) (*types.EmailToMailioMapping, error) {
	mapping := &types.EmailToMailioMapping{
		EncryptedEmail: user.EncryptedEmail,
		MailioAddress:  user.MailioAddress,
	}
	repo, err := us.repoSelector.ChooseDB(repository.MailioMapping)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// Check if email already exists
	existingResponse, eErr := repo.GetByID(ctx, mapping.EncryptedEmail)
	if eErr != nil {
		if eErr != types.ErrNotFound {
			return nil, eErr
		}
	}
	if existingResponse != nil {
		var existing types.EmailToMailioMapping
		mErr := repository.MapToObject(existingResponse, &existing)
		if mErr != nil {
			return nil, mErr
		}
		mapping.BaseDocument = existing.BaseDocument
	}
	sErr := repo.Save(ctx, mapping.EncryptedEmail, mapping)
	if sErr != nil {
		return nil, sErr
	}

	return mapping, nil
}

// finding user by email address (email address must be encrypted with scrypt)
func (us *UserService) FindUserByScryptEmail(scryptEmail string) (*types.EmailToMailioMapping, error) {
	repo, err := us.repoSelector.ChooseDB(repository.MailioMapping)
	if err != nil {
		return nil, err
	}
	return getUserByScryptEmail(repo, scryptEmail)
}
