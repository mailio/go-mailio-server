package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-core/did"
	coreErrors "github.com/mailio/go-mailio-core/errors"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type SelfSovereignService struct {
	didRepo repository.Repository
	vcsRepo repository.Repository
}

// Self Sovereign Service operates over Mailios DID and VC documents
func NewSelfSovereignService(dbSelector repository.DBSelector) *SelfSovereignService {
	didRepo, err := dbSelector.ChooseDB(repository.DID)
	if err != nil {
		panic(err)
	}
	vcsRepo, err := dbSelector.ChooseDB(repository.VCS)
	if err != nil {
		panic(err)
	}
	return &SelfSovereignService{
		didRepo: didRepo,
		vcsRepo: vcsRepo,
	}
}

// Stores the DID document in the database
func (ssi *SelfSovereignService) SaveDID(did *did.Document) (*did.Document, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	response, eErr := ssi.didRepo.GetByID(ctx, did.ID.String())
	if eErr != nil { // only error allowed is not found error
		if eErr != coreErrors.ErrNotFound {
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
		if eErr != coreErrors.ErrNotFound {
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

	authPath := "https://" + global.Conf.Mailio.Domain + global.Conf.Mailio.AuthenticationPath
	messagePath := "https://" + global.Conf.Mailio.Domain + global.Conf.Mailio.MessagingPath

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
	// newCredId := uuid.New().String()
	ID := []byte(mk.DID() + global.MailioDID.String())
	newID := util.Sha256Hex(ID)
	newVC := did.NewVerifiableCredential(global.MailioDID.String())
	newVC.IssuanceDate = time.Now().UTC()
	newVC.ID = newID
	credentialSubject := did.CredentialSubject{
		ID: mk.DID(),
		AuthorizedApplication: &did.AuthorizedApplication{
			ID:           mk.DID(),
			Domains:      []string{global.Conf.Mailio.Domain},
			ApprovalDate: time.Now(),
		},
	}
	newVC.CredentialSubject = credentialSubject
	newVC.CredentialStatus = &did.CredentialStatus{
		ID:   global.Conf.Mailio.Domain + "/api/v1/credentials/" + newID + "/status",
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
