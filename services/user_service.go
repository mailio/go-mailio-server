package services

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
)

type UserService struct {
	repoSelector *repository.CouchDBSelector
	restyClient  *resty.Client
	env          *types.Environment
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

	return &UserService{
		repoSelector: repoSelector,
		restyClient:  client,
		env:          env,
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

	// create required indexes
	iErr := repository.CreateUserDatabaseFolderCreatedIndex(userRepo, hexUser)
	xErr := repository.CreateDesign_SentToCountView(hexUser, "sent-to", "count-view")
	aErr := repository.CreateDesign_CountFromAddress(hexUser, "count", "from-address")
	arErr := repository.CreateDesign_CountFromAddressRead(hexUser, "count-read", "from-address-read")
	if errors.Join(iErr, aErr, arErr, xErr) != nil {
		return nil, errors.Join(iErr, aErr, arErr, xErr)
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
// func (us *UserService) GetMessage(address string, ID string) (*types.MailioMessage, error) {
// 	if ID == "" {
// 		return nil, types.ErrBadRequest
// 	}
// 	hexUser := "userdb-" + hex.EncodeToString([]byte(address))
// 	url := fmt.Sprintf("%s/%s", hexUser, ID)

// 	var mailioMessage types.MailioMessage
// 	var couchError types.CouchDBError
// 	response, rErr := us.restyClient.R().SetResult(&mailioMessage).SetError(&couchError).Get(url)
// 	if rErr != nil {
// 		global.Logger.Log(rErr.Error(), "failed to get message", hexUser)
// 		return nil, rErr
// 	}
// 	if response.IsError() {
// 		if response.StatusCode() == 404 {
// 			return nil, types.ErrNotFound
// 		}
// 		global.Logger.Log(response.String(), "failed to get message", hexUser, couchError.Error, couchError.Reason)
// 		return nil, fmt.Errorf("code: %s, reason: %s", couchError.Error, couchError.Reason)
// 	}

// 	return &mailioMessage, nil
// }

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
func (us *UserService) CountNumberOfSentByRecipientMessages(address string, recipient string, from int64, to int64) (*types.CouchDBCountDistinctFromResponse, error) {
	viewPath := "_design/sent-to/_view/count-view"
	hexUser := "userdb-" + hex.EncodeToString([]byte(address))

	// format: address, folder, timestamp
	params := url.Values{}
	params.Add("key", fmt.Sprintf("\"%s\"", recipient))
	params.Add("group_level", "1")

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
func (us *UserService) CountNumberOfReceivedMessages(address string, from string, isRead bool, fromTimestamp int64, toTimestamp int64) (*types.CouchDBCountDistinctFromResponse, error) {
	// query for couchdb statistics

	//_design/count-from/_view/count-from-address (how many messages are received from user)
	//_design/count-from/_view/count-from-address-read (how many messages are read)
	// startkey=["inbox", "0x1869cc058092317800727afa25981bfd2a3d0969", 0]&endkey=["inbox", "0x1869cc058092317800727afa25981bfd2a3d0969", \u0000]&group_level=1

	//expected response (for both views):
	/**
	{"rows":[
		{"key":["inbox"],"value":4},
		{"key":["sent"],"value":4}
	]}
	**/
	viewPath := "_design/count/_view/from-address"
	if isRead {
		viewPath = "_design/count-read/_view/from-address-read"
	}
	hexUser := "userdb-" + hex.EncodeToString([]byte(address))

	params := url.Values{}
	params.Add("startkey", fmt.Sprintf("[\"%s\",\"%s\",%d]", address, "", fromTimestamp))
	params.Add("endkey", fmt.Sprintf("[\"%s\",\"%s\", %d]", address, "\uffff", toTimestamp))
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

// upload attachment to s3
func (us *UserService) UploadAttachment(bucket, path string, content []byte) (string, error) {
	if len(content) == 0 {
		return "", types.ErrBadRequest
	}
	ioReader := bytes.NewReader(content)
	_, uErr := us.env.S3Uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(path),
		Body:   ioReader,
	})
	if uErr != nil {
		global.Logger.Log(uErr.Error(), "failed to upload attachment", path)
		return "", uErr
	}
	return fmt.Sprintf("s3://%s%s", global.Conf.Storage.Bucket, path), nil
}

// download attachment from s3
// func (us *UserService) DownloadAttachment(attachmentUrl string) ([]byte, error) {
// 	if attachmentUrl == "" {
// 		return nil, types.ErrBadRequest
// 	}
// 	splitted := strings.Split(attachmentUrl, "s3://"+global.Conf.Storage.Bucket+"/")
// 	if len(splitted) != 2 {
// 		return nil, types.ErrBadRequest
// 	}
// 	buf := aws.NewWriteAtBuffer([]byte{})
// 	_, err := us.env.S3Downloader.Download(buf, &s3manager.DownloadInput{
// 		Bucket: aws.String(global.Conf.Storage.Bucket),
// 		Key:    aws.String(attachmentUrl),
// 	})
// 	if err != nil {
// 		return nil, err
// 	}
// 	return buf.Bytes(), nil
// }
