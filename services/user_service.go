package services

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/url"
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
	ssiService := NewSelfSovereignService(repoSelector)

	return &UserService{
		repoSelector:       repoSelector,
		restyClient:        client,
		env:                env,
		userProfileService: upService,
		ssiService:         ssiService,
	}
}

// CreateUser creates a new user with the given email and password.
// It returns a pointer to an InputEmailPassword struct and an error (if any).
func (us *UserService) CreateUser(user *types.User, mk *did.MailioKey, databasePassword string) (*types.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// map sacrypt (encrryped email) address to mailio address
	_, errMu := us.MapEmailToMailioAddress(user)
	if errMu != nil {
		if errMu == types.ErrUserExists {
			return user, errMu
		}
		return nil, errMu
	}

	// validate if the domain is supported
	userDomain := strings.Split(user.Email, "@")[1]
	if !util.IsSupportedMailioDomain(userDomain) {
		return nil, types.ErrDomainNotFound
	}

	userRepo, rErr := us.repoSelector.ChooseDB(repository.User)
	if rErr != nil {
		return nil, rErr
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

	// create required indexes
	iErr := repository.CreateUserDatabaseFolderCreatedIndex(userRepo, hexUser)
	xErr := repository.CreateDesign_SentToCountView(hexUser, "sent-to", "count-view")
	aErr := repository.CreateDesign_CountFromAddress(hexUser, "count", "from-address")
	arErr := repository.CreateDesign_CountFromAddressRead(hexUser, "count-read", "from-address-read")
	if errors.Join(iErr, aErr, arErr, xErr) != nil {
		return nil, errors.Join(iErr, aErr, arErr, xErr)
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
		global.Logger.Log(httpResp.String(), "failed to save message", hexUser, postError.Error, postError.Reason)
		return nil, fmt.Errorf("code: %s, reason: %s", postError.Error, postError.Reason)
	}

	return mailioMessage, nil
}

// counts the number of sent messages from mailio user to specific recipient (regular email or mailio address)
func (us *UserService) CountNumberOfSentByRecipientMessages(address string, recipient string, from int64, to int64) (*types.CouchDBCountResponse, error) {
	viewPath := "_design/sent-to/_view/count-view"
	hexUser := "userdb-" + hex.EncodeToString([]byte(address))

	// format: address, folder, timestamp
	params := url.Values{}
	params.Add("key", fmt.Sprintf("\"%s\"", recipient))
	params.Add("group_level", "1")

	url := fmt.Sprintf("%s/%s?%s", hexUser, viewPath, params.Encode())

	var couchError types.CouchDBError
	var response types.CouchDBCountResponse

	httpResp, httpErr := us.restyClient.R().SetResult(&response).SetError(&couchError).Get(url)
	if httpErr != nil {
		global.Logger.Log(httpErr.Error(), "failed to send message", hexUser)
		return nil, httpErr
	}
	if httpResp.IsError() {
		global.Logger.Log(httpResp.String(), "failed to send message", hexUser, couchError.Error, couchError.Reason)
		return nil, fmt.Errorf("code: %s, reason: %s", couchError.Error, couchError.Reason)
	}
	return &response, nil
}

// counts the number of sent messages by user between two timestamps
func (us *UserService) CountNumberOfSentMessages(address string, from int64, to int64) (*types.CouchDBCountDistinctFromResponse, error) {
	viewPath := "_design/count/_view/from-address"
	hexUser := "userdb-" + hex.EncodeToString([]byte(address))

	// format: address, folder, timestamp
	params := url.Values{}
	params.Add("startkey", fmt.Sprintf("[\"%s\",\"%s\",%d]", address, "sent", from))
	params.Add("endkey", fmt.Sprintf("[\"%s\",\"%s\",%d]", address, "sent", to))
	params.Add("group_level", "2")

	url := fmt.Sprintf("%s/%s?%s", hexUser, viewPath, params.Encode())

	var couchError types.CouchDBError
	var response types.CouchDBCountDistinctFromResponse

	httpResp, httpErr := us.restyClient.R().SetResult(&response).SetError(&couchError).Get(url)
	if httpErr != nil {
		global.Logger.Log(httpErr.Error(), "failed to send message", hexUser)
		return nil, httpErr
	}
	if httpResp.IsError() {
		global.Logger.Log(httpResp.String(), "failed to send message", hexUser, couchError.Error, couchError.Reason)
		return nil, fmt.Errorf("code: %s, reason: %s", couchError.Error, couchError.Reason)
	}
	return &response, nil
}

// address is the user's mailio address, from is a message sender (it can be Mailio address or ordinary email address)
func (us *UserService) CountNumberOfMessages(address string, from string, folder string, isRead bool, fromTimestamp int64, toTimestamp int64) (*types.CouchDBCountDistinctFromResponse, error) {
	// query for couchdb statistics

	//_design/count-from/_view/count-from-address (how many messages are received from user)
	//_design/count-from/_view/count-from-address-read (how many messages are read)
	// startkey=["0x1869cc058092317800727afa25981bfd2a3d0969","", 0]&endkey=["0x1869cc058092317800727afa25981bfd2a3d0969", "\uffff", 213456789]&group_level=2
	// startkey=["test@example.com","sent", 0]&endkey=["test@example.com", "sent", 12344432342342]&group_level=2

	//expected response (for both views):
	/**
	{"rows":[
		{"key":["inbox"],"value":4},
		{"key":["sent"],"value":4}
	]}
	**/
	folderFrom := ""
	folderTo := "\uffff"
	if folder != "" {
		folderFrom = folder
		folderTo = folder
	}
	viewPath := "_design/count/_view/from-address"
	if isRead {
		viewPath = "_design/count-read/_view/from-address-read"
	}
	hexUser := "userdb-" + hex.EncodeToString([]byte(address))

	startKey := fmt.Sprintf("[\"%s\",\"%s\",%d]", from, folderFrom, fromTimestamp)
	endKey := fmt.Sprintf("[\"%s\",\"%s\",%d]", from, folderTo, toTimestamp)
	params := url.Values{}
	params.Add("startkey", startKey)
	params.Add("endkey", endKey)
	params.Add("group_level", "2")

	url := fmt.Sprintf("%s/%s?%s", hexUser, viewPath, params.Encode())

	var couchError types.CouchDBError
	var response types.CouchDBCountDistinctFromResponse

	httpResp, httpErr := us.restyClient.R().SetResult(&response).SetError(&couchError).Get(url)
	if httpErr != nil {
		global.Logger.Log(httpErr.Error(), "failed to send message", hexUser)
		return nil, httpErr
	}
	if httpResp.IsError() {
		global.Logger.Log(httpResp.String(), "failed to send message", hexUser, couchError.Error, couchError.Reason)
		return nil, fmt.Errorf("code: %s, reason: %s", couchError.Error, couchError.Reason)
	}
	return &response, nil
}
