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

	"github.com/go-kit/log/level"
	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
	"github.com/redis/go-redis/v9"
)

type SelfSovereignService struct {
	didRepo              repository.Repository
	vcsRepo              repository.Repository
	handshakeMappingRepo repository.Repository
	domainRepo           repository.Repository
	restyClient          *resty.Client
	env                  *types.Environment
}

// Self Sovereign Service operates over Mailios DID and VC documents
func NewSelfSovereignService(dbSelector repository.DBSelector, env *types.Environment) *SelfSovereignService {
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
	mappingRepo, err := dbSelector.ChooseDB(repository.MailioMapping)
	if err != nil {
		panic(err)
	}
	domainRepo, err := dbSelector.ChooseDB(repository.Domain)
	if err != nil {
		panic(err)
	}

	return &SelfSovereignService{
		didRepo:              didRepo,
		vcsRepo:              vcsRepo,
		handshakeMappingRepo: mappingRepo,
		domainRepo:           domainRepo,
		restyClient:          restyClient,
		env:                  env,
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
func (ssi *SelfSovereignService) StoreRegistrationSSI(mk *did.MailioKey) error {

	authPath := global.Conf.Mailio.ServerDomain + global.Conf.Mailio.AuthenticationPath
	messagePath := global.Conf.Mailio.ServerDomain + global.Conf.Mailio.MessagingPath

	userDIDDoc, didErr := did.NewMailioDIDDocument(mk, global.PublicKey, authPath, messagePath)
	if didErr != nil {
		return errors.New("failed to create DID document")
	}
	// store in database
	_, sdidErr := ssi.SaveDID(userDIDDoc)
	if sdidErr != nil {
		return errors.New("failed to store DID document")
	}

	// proof that user owns the email address at this domain
	ID := []byte(mk.DID() + global.MailioDID.String())
	newID := util.Sha256Hex(ID)
	newVC := did.NewVerifiableCredential(global.MailioDID.String())
	newVC.IssuanceDate = time.Now().UTC()
	newVC.ID = newID
	credentialSubject := did.CredentialSubject{
		ID: mk.DID(),
		AuthorizedApplication: &did.AuthorizedApplication{
			ID:           mk.DID(),
			Domains:      []string{global.Conf.Mailio.ServerDomain},
			ApprovalDate: time.Now(),
		},
	}
	newVC.CredentialSubject = credentialSubject
	newVC.CredentialStatus = &did.CredentialStatus{
		ID:   global.Conf.Mailio.ServerDomain + "/api/v1/credentials/" + newID,
		Type: "CredentialStatusList2017",
	}
	vcpErr := newVC.CreateProof(global.PrivateKey)
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

/**
 * Get the DID document for the given mailio address from local database
 * @param mailioAddress
 * @return DID document
 */
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
// FetchRemoteDID doesn't resolve domains since it expects already resolved domain
// Returns the DID document for the given web mailio address
// - ErrInvalidFormat when DID address not valid
// - ErrBadRequest when remote server returns code >= 400
// - ErrConflict when rate limit of remote server exceeded
// - ErrNotFound when DID address not found
func (ssi *SelfSovereignService) FetchRemoteDID(remoteDid *did.DID) (*did.Document, error) {
	domain := remoteDid.Value()
	if domain == global.Conf.Mailio.ServerDomain {
		return nil, types.ErrBadRequest
	}
	protocol := "https"
	if strings.Contains(domain, "localhost") || strings.Contains(domain, "127.0.0.1") {
		protocol = "http"
	}

	userAddress := remoteDid.Fragment()

	if userAddress == "" {
		return nil, types.ErrInvalidFormat
	}

	// finding a did document with the given user address checking all possible urls
	var didDoc did.Document

	response, rErr := ssi.restyClient.R().SetResult(&didDoc).Get(fmt.Sprintf("%s://%s/%s/did.json", protocol, domain, userAddress))
	if rErr != nil {
		level.Error(global.Logger).Log(rErr.Error(), "failed to validate recipient for ", domain)
		return nil, types.ErrBadRequest
	}
	if response.IsError() {
		if response.StatusCode() == http.StatusNotFound {
			level.Error(global.Logger).Log("recipient not found", "failed to validate recipient for ", domain)
			return nil, types.ErrBadRequest
		}
		if response.StatusCode() == http.StatusConflict {
			level.Error(global.Logger).Log("rate limit exceeded", "failed to validate recipient for ", domain)
			return nil, types.ErrConflict
		}
		level.Error(global.Logger).Log(response.String(), "failed to validate recipient for ", domain)
		return nil, types.ErrBadRequest
	}

	return &didDoc, nil
}

// cacheSenderDIDDocument caches the sender DID document (if not already cached)
func (ssi *SelfSovereignService) FetchDIDByWebDID(fromDID did.DID) (*did.Document, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	host := global.Conf.Mailio.ServerDomain

	key := fmt.Sprintf("%s%s", global.REDIS_DID_CACHE_PREFIX, fromDID)
	didBytes, err := ssi.env.RedisClient.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			// cache the DID document
			var result did.Document

			// check if local server (don't query it over network due to "rate limits")
			if fromDID.Value() == host {
				r, rErr := ssi.GetDIDDocument(fromDID.Fragment())
				if rErr != nil {
					level.Error(global.Logger).Log(rErr.Error(), "failed to validate recipient", fromDID.Fragment())
					return nil, rErr
				} else {
					result = *r
				}
			} else {
				// remote fetch did
				r, rErr := ssi.FetchRemoteDID(&fromDID)
				if rErr != nil {
					level.Error(global.Logger).Log(rErr.Error(), "failed to validate remote recipient", fromDID.Fragment())
					return nil, rErr
				} else {
					result = *r
				}
			}
			// cache the DID document
			didBytes, mErr := json.Marshal(result)
			if mErr != nil {
				level.Error(global.Logger).Log(mErr.Error(), "failed to marshal DID document for caching")
				return nil, mErr
			}
			// cache for 24 hours
			_, cErr := ssi.env.RedisClient.Set(ctx, key, didBytes, global.REDIS_DID_CACHE_TTL).Result()
			if cErr != nil {
				level.Error(global.Logger).Log(cErr.Error(), "failed to cache DID document for caching")
				return nil, cErr
			}
			return &result, nil
		}
	}
	// document already cached, no need to cache, but just extend the expiration time
	_, cErr := ssi.env.RedisClient.Expire(ctx, key, global.REDIS_DID_CACHE_TTL).Result()
	if cErr != nil {
		level.Error(global.Logger).Log(cErr.Error(), "failed to extend expiration time for cached DID document")
		return nil, cErr
	}
	var didDoc did.Document
	uErr := json.Unmarshal([]byte(didBytes), &didDoc)
	if uErr != nil {
		level.Error(global.Logger).Log(uErr.Error(), "failed to unmarshal cached DID document")
		return nil, uErr
	}
	return &didDoc, nil
}
