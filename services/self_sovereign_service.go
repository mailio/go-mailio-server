package services

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/mailio/go-mailio-core/did"
	coreErrors "github.com/mailio/go-mailio-core/errors"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
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

	userDIDDoc, didErr := did.NewMailioDIDDocument(mk, global.PublicKey)
	if didErr != nil {
		return errors.New("failed to create DID document")
	}
	// store in database
	_, sdidErr := ssi.SaveDID(userDIDDoc)
	if sdidErr != nil {
		return errors.New("failed to store DID document")
	}

	// proof that user owns the email address at this domain
	newCredId := uuid.New().String()
	newVC := did.NewVerifiableCredential(global.MailioDID.String())
	newVC.IssuanceDate = time.Now().UTC()
	newVC.ID = newCredId
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
		ID:   global.Conf.Mailio.Domain + "/api/v1/credentials/" + newCredId + "/status",
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

	//TODO! impelement index on credentialSubject/id and then design document to be able to query all VCs for a user
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
