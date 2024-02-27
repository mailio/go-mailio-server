package services

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
)

type UserService struct {
	repoSelector *repository.CouchDBSelector
	restyClient  *resty.Client
}

func NewUserService(repoSelector *repository.CouchDBSelector) *UserService {
	if repoSelector == nil {
		panic("repoSelector cannot be nil")
	}
	repoUrl := global.Conf.CouchDB.Scheme + "://" + global.Conf.CouchDB.Host
	if global.Conf.CouchDB.Port != 0 {
		repoUrl += ":" + strconv.Itoa(global.Conf.CouchDB.Port)
	}
	client := resty.New().
		SetTimeout(time.Second*10).
		SetBasicAuth(global.Conf.CouchDB.Username, global.Conf.CouchDB.Password).
		SetHeader("Content-Type", "application/json").
		SetHeader("Accept", "application/json").
		SetBaseURL(repoUrl).
		SetDebug(false)

	return &UserService{
		repoSelector: repoSelector,
		restyClient:  client,
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

		headResponse, hErr := c.R().Get(hexUser)
		if hErr != nil {
			return nil, errors.New("failed to create user database")
		}
		if headResponse.StatusCode() == 200 {
			break
		}

		//TODO! is this really the best way to wait for database to be created?
		if headResponse.StatusCode() == 404 {
			backoff := int(100 * math.Pow(2, float64(i)))
			time.Sleep(time.Duration(backoff) * time.Millisecond)
			continue
		} else {
			return nil, errors.New("failed to create user database")
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

// Retrieves mailio message from users database by ID
func (us *UserService) GetMessage(address string, ID string) (*types.MailioMessage, error) {
	if ID == "" {
		return nil, types.ErrBadRequest
	}
	hexUser := "userdb-" + hex.EncodeToString([]byte(address))
	url := fmt.Sprintf("%s/%s", hexUser, ID)

	var mailioMessage types.MailioMessage
	var couchError types.CouchDBError
	response, rErr := us.restyClient.R().SetResult(&mailioMessage).SetError(&couchError).Get(url)
	if rErr != nil {
		global.Logger.Log(rErr.Error(), "failed to get message", hexUser)
		return nil, rErr
	}
	if response.IsError() {
		if response.StatusCode() == 404 {
			return nil, types.ErrNotFound
		}
		global.Logger.Log(response.String(), "failed to get message", hexUser, couchError.Error, couchError.Reason)
		return nil, fmt.Errorf("code: %s, reason: %s", couchError.Error, couchError.Reason)
	}

	return &mailioMessage, nil
}

// Stores mailio message to users database
func (us *UserService) SaveMessage(userAddress string, mailioMessage *types.MailioMessage) (*types.MailioMessage, error) {

	if mailioMessage.Folder == "" || mailioMessage.ID == "" || mailioMessage.Created == 0 {
		return nil, types.ErrBadRequest
	}
	mailioMessage.BaseDocument.ID = mailioMessage.ID

	hexUser := "userdb-" + hex.EncodeToString([]byte(userAddress))
	url := fmt.Sprintf("%s/%s", hexUser, mailioMessage.ID)

	var postResult types.CouchDBResponse
	var postError types.CouchDBError
	httpResp, httpErr := us.restyClient.R().SetBody(mailioMessage).SetResult(&postResult).SetError(&postError).Put(url)
	if httpErr != nil {
		global.Logger.Log(httpErr.Error(), "failed to send message", hexUser)
		return nil, httpErr
	}
	if httpResp.IsError() {
		global.Logger.Log(httpResp.String(), "failed to send message", hexUser, postError.Error, postError.Reason)
		return nil, fmt.Errorf("code: %s, reason: %s", postError.Error, postError.Reason)
	}

	return mailioMessage, nil
}
