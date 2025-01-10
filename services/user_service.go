package services

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type UserService struct {
	repoSelector       *repository.CouchDBSelector
	restyClient        *resty.Client
	env                *types.Environment
	userProfileService *UserProfileService
	ssiService         *SelfSovereignService
}

func NewUserService(repoSelector *repository.CouchDBSelector, env *types.Environment) *UserService {
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

	upService := NewUserProfileService(repoSelector, env)
	ssiService := NewSelfSovereignService(repoSelector, env)

	return &UserService{
		repoSelector:       repoSelector,
		restyClient:        client,
		env:                env,
		userProfileService: upService,
		ssiService:         ssiService,
	}
}

// CreateDatabase creates a new database for the user with the given email and password.
// It returns an error (if any).
func (us *UserService) CreateDatabase(user *types.User, databasePassword string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userRepo, rErr := us.repoSelector.ChooseDB(repository.User)
	if rErr != nil {
		global.Logger.Log(rErr, "Failed to choose repository")
		return rErr
	}
	err := userRepo.Save(ctx,
		fmt.Sprintf("%s:%s", "org.couchdb.user", user.MailioAddress),
		map[string]interface{}{
			"name":           user.MailioAddress,
			"password":       databasePassword,
			"roles":          []string{},
			"type":           "user",
			"encryptedEmail": user.EncryptedEmail,
			"created":        user.Created})
	if err != nil {
		global.Logger.Log(err, "Failed to register user")
		return err
	}

	hexUser := "userdb-" + hex.EncodeToString([]byte(user.MailioAddress)) // MailioAddress already hex

	// wait for database to be created
	c := userRepo.GetClient().(*resty.Client)

	for i := 1; i < 5; i++ {

		headResponse, hErr := c.R().Get(hexUser)
		if hErr != nil {
			global.Logger.Log(hErr, "failed to create user database")
			return errors.New("failed to create user database")
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
			global.Logger.Log(headResponse.String(), "failed to create user database")
			return errors.New("failed to create user database")
		}
	}

	// Create folder index: created, folder
	indErr := repository.CreateFolderIndex(userRepo, hexUser)
	if indErr != nil {
		global.Logger.Log(indErr, "failed to create folder index")
		return indErr
	}
	return nil
}

// CreateUser creates a new user with the given email and password.
// It returns a pointer to an InputEmailPassword struct and an error (if any).
func (us *UserService) CreateUser(user *types.User, mk *did.MailioKey, databasePassword string) (*types.User, error) {
	// validate if the domain is supported
	userDomain := strings.Split(user.Email, "@")[1]
	if !util.IsSupportedMailioDomain(userDomain) {
		return nil, types.ErrDomainNotFound
	}
	// map sacrypt (encrryped email) address to mailio address
	_, errMu := us.MapEmailToMailioAddress(user)
	if errMu != nil {
		if errMu == types.ErrUserExists {
			return user, errMu
		}
		return nil, errMu
	}

	dbErr := us.CreateDatabase(user, databasePassword)
	if dbErr != nil {
		global.Logger.Log(dbErr, "failed to create database")
		return nil, dbErr
	}

	_, upErr := us.userProfileService.Save(user.MailioAddress, &types.UserProfile{
		Enabled:   true,
		DiskSpace: global.Conf.Mailio.DiskSpace,
		Domain:    userDomain,
		Created:   time.Now().UTC().UnixMilli(),
		Modified:  time.Now().UTC().UnixMilli(),
	})
	if upErr != nil {
		global.Logger.Log(upErr, "failed to save user profile")
		return nil, upErr
	}

	ssiErr := us.ssiService.StoreRegistrationSSI(mk)
	if ssiErr != nil {
		global.Logger.Log(ssiErr, "failed to store registration SSI")
		return nil, ssiErr
	}

	return user, nil
}

// Maps encrypted email to mailio address so outside users can request per user email if they know it
func (us *UserService) MapEmailToMailioAddress(user *types.User) (*types.EmailToMailioMapping, error) {

	// since it's base64 encoded, we need to escape it
	id := base64.RawStdEncoding.EncodeToString([]byte(user.EncryptedEmail))

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
	existingResponse, eErr := repo.GetByID(ctx, id)
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
	sErr := repo.Save(ctx, id, mapping)
	if sErr != nil {
		return nil, sErr
	}

	return mapping, nil
}

// finding user by email address (email address must be encrypted with scrypt)
func (us *UserService) FindUserByScryptEmail(scryptEmail string) (*types.EmailToMailioMapping, error) {
	repo, err := us.repoSelector.ChooseDB(repository.MailioMapping)
	if err != nil {
		global.Logger.Log(err, "failed to choose repository")
		return nil, err
	}
	return getUserByScryptEmail(repo, scryptEmail)
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
		global.Logger.Log(httpErr.Error(), "failed to save message", hexUser)
		return nil, httpErr
	}
	if httpResp.IsError() {
		stackTrace := string(debug.Stack())
		global.Logger.Log(httpResp.String(), "failed to save message", hexUser, postError.Error, postError.Reason)
		return nil, fmt.Errorf("code: %s, reason: %s, trace: %v", postError.Error, postError.Reason, stackTrace)
	}

	return mailioMessage, nil
}
