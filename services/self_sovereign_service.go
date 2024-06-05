package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type SelfSovereignService struct {
	didRepo     repository.Repository
	vcsRepo     repository.Repository
	restyClient *resty.Client
}

// Self Sovereign Service operates over Mailios DID and VC documents
func NewSelfSovereignService(dbSelector repository.DBSelector) *SelfSovereignService {
	initialWaitTime := 1 * time.Second
	maxWaitTime := 20 * time.Second
	restyClient := resty.New().
		SetRetryCount(3).
		SetRetryWaitTime(initialWaitTime).
		SetRetryMaxWaitTime(maxWaitTime)
	// Define a custom exponential backoff strategy
	restyClient = restyClient.AddRetryCondition(func(response *resty.Response, err error) bool {
		// Check if the response status code indicates a server error (5xx)
		if response != nil && response.StatusCode() >= http.StatusConflict {
			return true
		}
		return false
	})
	// Optional: Customize the backoff algorithm
	restyClient = restyClient.SetRetryAfter(func(client *resty.Client, resp *resty.Response) (time.Duration, error) {
		// Calculate exponential backoff based on the retry attempt
		retryAttempt := resp.Request.Attempt
		waitTime := math.Pow(2, float64(retryAttempt)) * float64(initialWaitTime)

		// Ensure the wait time does not exceed the maximum wait time
		if waitTime > float64(maxWaitTime) {
			waitTime = float64(maxWaitTime)
		}

		return time.Duration(waitTime), nil
	})

	didRepo, err := dbSelector.ChooseDB(repository.DID)
	if err != nil {
		panic(err)
	}
	vcsRepo, err := dbSelector.ChooseDB(repository.VCS)
	if err != nil {
		panic(err)
	}
	return &SelfSovereignService{
		didRepo:     didRepo,
		vcsRepo:     vcsRepo,
		restyClient: restyClient,
	}
}

// Stores the DID document in the database
func (ssi *SelfSovereignService) SaveDID(did *did.Document) (*did.Document, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	response, eErr := ssi.didRepo.GetByID(ctx, did.ID.String())
	if eErr != nil { // only error allowed is not found error
		if eErr != types.ErrNotFound {
			return nil, eErr
		}
	}
	// converted to mailio DID document
	mailioDid := types.DidDocument{
		DID: did,
	}
	// check existing
	var existing types.DidDocument
	if response != nil {
		mErr := repository.MapToObject(response, &existing)
		if mErr != nil {
			return nil, mErr
		}
		mailioDid.BaseDocument = existing.BaseDocument
	}
	err := ssi.didRepo.Save(ctx, did.ID.String(), mailioDid)
	if err != nil {
		return nil, err
	}
	return did, nil
}

// Stores the Verifiable Credential in the database
func (ssi *SelfSovereignService) SaveVC(vc *did.VerifiableCredential) (*did.VerifiableCredential, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	response, eErr := ssi.vcsRepo.GetByID(ctx, vc.ID)
	if eErr != nil { // only error allowed is not found error
		if eErr != types.ErrNotFound {
			return nil, eErr
		}
	}
	// converted to mailio DID document
	mailioVC := types.VerifiableCredentialDocument{
		VC: vc,
	}
	// check existing
	var existing types.VerifiableCredentialDocument
	if response != nil {
		mErr := repository.MapToObject(response, &existing)
		if mErr != nil {
			return nil, mErr
		}
		mailioVC.BaseDocument = existing.BaseDocument
	}
	err := ssi.vcsRepo.Save(ctx, vc.ID, mailioVC)
	if err != nil {
		return nil, err
	}
	return vc, nil
}

// Stores the users DID document and signs a VC with servers private key that proves ownership of the email address
func (ssi *SelfSovereignService) StoreRegistrationSSI(mk *did.MailioKey, userDomain string) error {

	authPath := userDomain + global.Conf.Mailio.AuthenticationPath
	messagePath := userDomain + global.Conf.Mailio.MessagingPath

	// get domain public key
	if _, ok := global.PublicKeyByDomain[userDomain]; !ok {
		global.Logger.Log("public key not found", "missing public key for domain")
		return types.ErrDomainNotFound
	}
	publicKey := global.PublicKeyByDomain[userDomain]
	// get domain private key
	if _, ok := global.PrivateKeysByDomain[userDomain]; !ok {
		global.Logger.Log("private key not found", "missing private key for domain")
		return types.ErrDomainNotFound
	}
	privateKey := global.PrivateKeysByDomain[userDomain]

	userDIDDoc, didErr := did.NewMailioDIDDocument(mk, publicKey, authPath, messagePath)
	if didErr != nil {
		return errors.New("failed to create DID document")
	}
	// store in database
	_, sdidErr := ssi.SaveDID(userDIDDoc)
	if sdidErr != nil {
		return errors.New("failed to store DID document")
	}

	// proof that user owns the email address at this domain
	// newCredId := uuid.New().String()
	if _, ok := global.MailioDIDByDomain[userDomain]; !ok {
		global.Logger.Log("mailio DID not found", "missing mailio DID for domain")
		return types.ErrDomainNotFound
	}
	mailioDID := global.MailioDIDByDomain[userDomain]
	ID := []byte(mk.DID() + mailioDID.String())
	newID := util.Sha256Hex(ID)
	newVC := did.NewVerifiableCredential(mailioDID.String())
	newVC.IssuanceDate = time.Now().UTC()
	newVC.ID = newID
	credentialSubject := did.CredentialSubject{
		ID: mk.DID(),
		AuthorizedApplication: &did.AuthorizedApplication{
			ID:           mk.DID(),
			Domains:      []string{userDomain},
			ApprovalDate: time.Now(),
		},
	}
	newVC.CredentialSubject = credentialSubject
	newVC.CredentialStatus = &did.CredentialStatus{
		ID:   userDomain + "/api/v1/credentials/" + newID + "/status",
		Type: "CredentialStatusList2017",
	}
	vcpErr := newVC.CreateProof(privateKey)
	if vcpErr != nil {
		return errors.New("failed to create verifiable credential proof")
	}

	//store in database the newly generated VC
	_, vcsErr := ssi.SaveVC(newVC)
	if vcsErr != nil {
		return errors.New("failed to store verifiable credential")
	}
	return nil
}

// Returns the DID document for the given mailio address
func (ssi *SelfSovereignService) GetDIDDocument(mailioAddress string) (*did.Document, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	response, eErr := ssi.didRepo.GetByID(ctx, did.DIDKeyPrefix+mailioAddress)
	if eErr != nil { // only error allowed is not found error
		return nil, eErr
	}
	var didDoc types.DidDocument
	mErr := repository.MapToObject(response, &didDoc)
	if mErr != nil {
		return nil, mErr
	}
	return didDoc.DID, nil
}

// Returns the DID document for the given mailio address
func (ssi *SelfSovereignService) GetVCByID(ID string) (*did.VerifiableCredential, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	response, eErr := ssi.vcsRepo.GetByID(ctx, ID)
	if eErr != nil { // only error allowed is not found error
		return nil, eErr
	}
	var vcDoc types.VerifiableCredentialDocument
	mErr := repository.MapToObject(response, &vcDoc)
	if mErr != nil {
		return nil, mErr
	}
	return vcDoc.VC, nil
}

func (ssi *SelfSovereignService) GetAuthorizedAppVCByAddress(address string, issuerDID string) (*did.VerifiableCredential, error) {
	ID := []byte(did.DIDKeyPrefix + address + issuerDID)
	hexID := util.Sha256Hex(ID)
	return ssi.GetVCByID(hexID)
}

// List all VCs from a specific subject (where subject is a mailio DID)
func (ssi *SelfSovereignService) ListSubjectVCs(address string, limit int, bookmark string) ([]*did.VerifiableCredential, error) {
	query := map[string]interface{}{
		"selector": map[string]interface{}{
			"vc.credentialSubject.id": "did:mailio:" + address,
		},
		"use_index": "credentialSubjectID-index",
		"limit":     limit,
	}
	c := ssi.vcsRepo.GetClient().(*resty.Client)
	response, rErr := c.R().SetBody(query).Post(fmt.Sprintf("%s/_find?bookmark=%s", repository.VCS, bookmark))
	if rErr != nil {
		return nil, rErr
	}
	var listDocs map[string]interface{}
	uErr := json.Unmarshal(response.Body(), &listDocs)
	if uErr != nil {
		return nil, uErr
	}
	list := make([]*did.VerifiableCredential, 0)

	for _, docMap := range listDocs["docs"].([]interface{}) {
		vcMap := docMap.(map[string]interface{})
		var doc *types.VerifiableCredentialDocument
		vcMapBytes, vcErr := json.Marshal(vcMap)
		vcErrU := json.Unmarshal(vcMapBytes, &doc)
		if errors.Join(vcErr, vcErrU) != nil {
			return nil, errors.Join(vcErr, vcErrU)
		}
		list = append(list, doc.VC)
	}

	return list, nil
}

// FetchRemoteDID parses the WEB did and fetched DID document from the remote server
// Returns the DID document for the given web mailio address
// - ErrInvalidFormat when DID address not valid
// - ErrBadRequest when remote server returns code >= 400
// - ErrConflict when rate limit of remote server exceeded
// - ErrNotFound when DID address not found
func (ssi *SelfSovereignService) FetchRemoteDID(remoteDid *did.DID) (*did.Document, error) {
	url := remoteDid.Value()
	if url == global.Conf.Host {
		return nil, types.ErrBadRequest
	}
	protocol := "https"
	if strings.Contains(url, "localhost") || strings.Contains(url, "127.0.0.1") {
		protocol = "http"
	}

	userAddress := remoteDid.Fragment()

	if userAddress == "" {
		return nil, types.ErrInvalidFormat
	}

	var didDoc did.Document
	response, rErr := ssi.restyClient.R().SetResult(&didDoc).Get(fmt.Sprintf("%s://%s/%s/did.json", protocol, url, userAddress))
	if rErr != nil {
		global.Logger.Log(rErr.Error(), "failed to validate recipient")
		return nil, rErr
	}
	if response.IsError() {
		if response.StatusCode() == http.StatusNotFound {
			global.Logger.Log("recipient not found", "failed to validate recipient")
			return nil, types.ErrNotFound
		}
		if response.StatusCode() == http.StatusConflict {
			global.Logger.Log(response.String(), "rate limit exceeded")
			return nil, types.ErrConflict
		}
		global.Logger.Log(response.String(), "failed to validate recipient")
		return nil, types.ErrBadRequest

	}
	return &didDoc, nil
}
