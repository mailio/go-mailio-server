package services

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	coreErrors "github.com/mailio/go-mailio-core/errors"
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
	err := userRepo.Save(ctx, fmt.Sprintf(":%s", user.MailioAddress), map[string]interface{}{"email": user.Email, "password": databasePassword, "roles": []string{}, "type": "user"})
	if err != nil {
		global.Logger.Log(err, "Failed to register user")
		return nil, err
	}

	hexEmail := "userdb-" + user.MailioAddress // MailioAddress already hex

	// wait for database to be created
	for i := 1; i < 5; i++ {
		_, hErr := userRepo.GetByID(ctx, hexEmail)
		if hErr != nil {
			if errors.Is(hErr, coreErrors.ErrNotFound) {
				backoff := int(100 * math.Pow(2, float64(i)))
				time.Sleep(time.Duration(backoff) * time.Millisecond)
				continue
			} else {
				return nil, hErr
			}
		}
	}

	// create index on database
	folderIndex := map[string]interface{}{
		"index": map[string]interface{}{
			"fields": []map[string]interface{}{{"folder": "desc"}, {"created": "desc"}},
		},
		"name": "folder-index",
		"type": "json",
		"ddoc": "folder-index",
	}
	err = userRepo.Save(ctx, fmt.Sprintf("/%s/_index", hexEmail), folderIndex)
	if err != nil {
		return nil, err
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
	existing, eErr := repo.GetByID(ctx, mapping.EncryptedEmail)
	if eErr != nil {
		if eErr != coreErrors.ErrNotFound {
			return nil, eErr
		}
	}
	if existing != nil {
		return nil, coreErrors.ErrUserExists
	}
	sErr := repo.Save(ctx, mapping.EncryptedEmail, mapping)
	if sErr != nil {
		return nil, sErr
	}

	return mapping, nil
}
