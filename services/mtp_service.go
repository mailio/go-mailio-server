package services

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/go-kit/log/level"
	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type MtpService struct {
	domainRepo    repository.Repository
	handshakeRepo repository.Repository
	mappingRepo   repository.Repository
	restyClient   *resty.Client
	ssiService    *SelfSovereignService
}

func NewMtpService(dbSelector repository.DBSelector) *MtpService {
	domainRepo, err := dbSelector.ChooseDB(repository.Domain)
	if err != nil {
		level.Error(global.Logger).Log("msg", "error while choosing db", "err", err)
		panic(err)
	}
	handshakeRepo, err := dbSelector.ChooseDB(repository.Handshake)
	if err != nil {
		level.Error(global.Logger).Log("msg", "error while choosing db", "err", err)
		panic(err)
	}
	mappingRepo, err := dbSelector.ChooseDB(repository.MailioMapping)
	if err != nil {
		level.Error(global.Logger).Log("msg", "error while choosing db", "err", err)
		panic(err)
	}
	ssiService := NewSelfSovereignService(dbSelector)
	restyClient := resty.New().SetRetryCount(3).SetRetryWaitTime(5 * time.Second)
	return &MtpService{domainRepo: domainRepo, handshakeRepo: handshakeRepo, mappingRepo: mappingRepo, ssiService: ssiService, restyClient: restyClient}
}

// Lookup handshakes locally and if not found
// then request from remote servers
func (mtp *MtpService) LookupHandshakes(senderAddress string, inputLookups []types.HandshakeLookup) ([]*types.HandshakeContent, []*types.HandshakeLookup, error) {

	// resolve domain from the lookups

	// Create a map for quick lookup of local domains
	localDomainMap := make(map[string]string)
	for _, localDomain := range global.Conf.Mailio.DomainConfig {
		localDomainMap[localDomain.Domain] = ""
	}

	localLookups := []types.HandshakeLookup{}
	remoteLookups := map[string][]types.HandshakeLookup{}
	for _, lookup := range inputLookups {
		lookupEmailParsed, lepErr := mail.ParseAddress(lookup.Email)
		if lepErr != nil {
			global.Logger.Log("msg", "failed to parse email address", "err", lepErr)
			return nil, nil, lepErr
		}
		lookupEmailParsed.Address = strings.ToLower(lookupEmailParsed.Address)
		lookupDomain := strings.Split(lookupEmailParsed.Address, "@")[1]
		// check if local or remote
		if _, ok := localDomainMap[lookupDomain]; ok {
			localLookups = append(localLookups, lookup)
		} else {
			// remote domain
			remoteLookups[lookupDomain] = append(remoteLookups[lookupDomain], lookup)
		}
	}

	// first check if we have the handshakes in the local database
	found, notFound, err := mtp.LocalHandshakeLookup(senderAddress, localLookups)
	if err != nil {
		return nil, nil, err
	}

	for domain, handshakeLookups := range remoteLookups {
		domainResults, dErr := mtp.requestHandshakeFromRemoteServer(senderAddress, handshakeLookups, domain)
		if dErr != nil {
			return nil, nil, dErr
		}
		for _, domainHandshakes := range domainResults {
			handshakes := domainHandshakes.HandshakeResponse.Handshakes
			found = append(found, handshakes...)
		}
	}
	return found, notFound, nil
}

// Request handshake from remote server calling /api/v1/mtp/handshake endpoint
// returns list of handshakes signed by the remote server
// if handshake older than 24 hours - it will not be returned

func (mtp *MtpService) requestHandshakeFromRemoteServer(senderAddress string, handshakeLookups []types.HandshakeLookup, domain string) ([]types.HandshakeSignedResponse, error) {
	if len(handshakeLookups) == 0 {
		return nil, types.ErrBadRequest
	}

	output := []types.HandshakeSignedResponse{}

	domainObject, resErr := resolveDomain(mtp.domainRepo, domain, false)
	if resErr != nil {
		return nil, resErr
	}

	// create handshake request objects signed by this server and request handshake from the domain
	request := &types.HandshakeSignedRequest{
		SenderDomain: global.Conf.Mailio.ServerDomain,
		HandshakeRequest: types.HandshakeRequest{
			SenderAddress:                senderAddress,
			ReturnDefaultServerHandshake: true,
			HandshakeLookups:             handshakeLookups,
			HandshakeHeader: types.LookupHeader{
				SignatureScheme:       types.Signature_Scheme_EdDSA_X25519,
				Timestamp:             time.Now().UnixMilli(),
				EmailLookupHashScheme: types.EmailLookupHashScheme_SC_N32768_R8_P1_L32_B64,
			},
		},
	}
	cborPayload, cErr := util.CborEncode(request.HandshakeRequest)
	if cErr != nil {
		level.Error(global.Logger).Log("msg", "failed to cbor encode request", "err", cErr)
		return nil, cErr
	}

	signature, sErr := util.Sign(cborPayload, global.PrivateKey)
	if sErr != nil {
		level.Error(global.Logger).Log("msg", "failed to sign request", "err", sErr)
		return nil, sErr
	}
	request.CborPayloadBase64 = base64.StdEncoding.EncodeToString(cborPayload)
	request.SignatureBase64 = base64.StdEncoding.EncodeToString(signature)

	// send request to domain (API endpoint: /api/v1/mtp/handshake)
	var signedResponse types.HandshakeSignedResponse
	response, rErr := mtp.restyClient.R().SetHeader("Content-Type", "application/json").
		SetBody(request).SetResult(&signedResponse).Post("https://" + domainObject.Name + "/api/v1/mtp/handshake")
	if rErr != nil {
		level.Error(global.Logger).Log("msg", "failed to request handshake", "err", rErr)
		return nil, rErr
	}
	if response.IsError() {
		level.Error(global.Logger).Log("msg", "failed to request handshake", "err", response.Error())
		return nil, response.Error().(error)
	}
	rcborPayload, rcErr := base64.StdEncoding.DecodeString(signedResponse.CborPayloadBase64)
	rsignature, rsErr := base64.StdEncoding.DecodeString(signedResponse.SignatureBase64)
	if errors.Join(rcErr, rsErr) != nil {
		level.Error(global.Logger).Log("msg", "failed to decode response", "err", errors.Join(rcErr, rsErr))
		return nil, types.ErrSignatureInvalid
	}

	isValid, rsErr := util.Verify(rcborPayload, rsignature, domainObject.MailioPublicKey)
	if rsErr != nil {
		level.Error(global.Logger).Log("msg", "failed to verify response", "err", rsErr)
		return nil, types.ErrSignatureInvalid
	}
	if !isValid {
		level.Error(global.Logger).Log("msg", "failed to verify response", "err", "invalid signature")
		return nil, types.ErrSignatureInvalid
	}
	output = append(output, signedResponse)
	return output, nil
}

// Handshake lookup method for Mailio Transfer Protocol
// returns list of handshakes based on the lookup criteria
func (mtp *MtpService) LocalHandshakeLookup(senderAddress string, lookups []types.HandshakeLookup) (found []*types.HandshakeContent, notFound []*types.HandshakeLookup, outputErr error) {

	found = []*types.HandshakeContent{}
	notFound = []*types.HandshakeLookup{}

	for _, lookup := range lookups {
		var shake *types.StoredHandshake
		var err error

		switch {
		case lookup.ID != "":
			shake, err = GetByID(mtp.handshakeRepo, lookup.ID)
		case lookup.Address != "":
			shake, err = GetByMailioAddress(mtp.handshakeRepo, lookup.Address, senderAddress)
		case lookup.EmailHash != "":
			mappedUser, userErr := getUserByScryptEmail(mtp.handshakeRepo, lookup.EmailHash)
			if userErr != nil {
				err = userErr
				break
			}
			shake, err = GetByMailioAddress(mtp.handshakeRepo, mappedUser.MailioAddress, senderAddress)
		default:
			outputErr = types.ErrBadRequest
			return
		}

		if err != nil {
			if err == types.ErrNotFound {
				// get local server if no user specific one exists handshake
				notFound = append(notFound, &lookup)
				continue
			}
			level.Error(global.Logger).Log("error", err)
			outputErr = err
			return
		}
		found = append(found, &shake.Content)
	}
	return
}

// Resolve domain from the domain repository
func (mtp *MtpService) ResolveDomain(domain string, forceDiscovery bool) (*types.Domain, error) {
	resolvedDomain, err := resolveDomain(mtp.domainRepo, domain, forceDiscovery)
	if err != nil {
		return nil, err
	}
	return resolvedDomain, nil
}

// GetServerDIDDocument retrieves the server DID document from the domain
func (mtp *MtpService) GetServerDIDDocument(domain string) (*did.Document, error) {

	senderServerDIDUrl := "https://" + domain + "/.well-known/did.json"
	if strings.Contains(domain, "localhost") || strings.Contains(domain, "127.0.0.1") {
		senderServerDIDUrl = "http://" + domain + "/.well-known/did.json"
	}
	var serverDIDDocument did.Document
	serverResponse, srvErr := mtp.restyClient.R().SetResult(&serverDIDDocument).Get(senderServerDIDUrl)
	if srvErr != nil {
		global.Logger.Log(srvErr.Error(), "failed to retrieve sender server DID", senderServerDIDUrl)
		return nil, fmt.Errorf("failed to retrieve sender server DID: %v", srvErr)
	}
	if serverResponse.IsError() {
		global.Logger.Log(serverResponse.String(), "failed to retrieve sender server DID", senderServerDIDUrl)
		return nil, fmt.Errorf("failed to retrieve sender server DID: %v", serverResponse.Error())
	}
	return &serverDIDDocument, nil
}

// FetchDIDDocuments fetches DID documents for a list of email addresses
// FetchDIDDocuments separates local and remote domains and fetches DID documents accordingly
// Returns a list of found DID documents and a list of not found email addresses
// Errors:
//
//	ErrInvalidEmail when email address is not valid
//	ErrBadRequest when remote server returns code >= 400
func (mtp *MtpService) FetchDIDDocuments(userMailioAddress string, didLookups []*types.DIDLookup) (found []*did.Document, notFound []*types.DIDLookup, err error) {
	// Create a map for quick lookup of local domains
	localLookups, remoteLookups, err := getLocalAndRemoteRecipients(didLookups)
	if err != nil {
		// invalid email addressess found
		return nil, nil, types.ErrInvalidEmail
	}
	found, notFound, err = mtp.GetLocalDIDDocumentsByEmailHash(localLookups)
	if err != nil {
		return nil, nil, err
	}

	// resolve remote lookups
	remoteFound, remoteNotFound, rErr := mtp.FetchRemoteDIDByEmailHash(userMailioAddress, remoteLookups)
	if rErr != nil {
		return nil, nil, rErr
	}
	found = append(found, remoteFound...)
	notFound = append(notFound, remoteNotFound...)

	return found, notFound, nil
}

// GetLocalDIDDocuments fetches DID documents for a list of email addresses with corresponding email hashes
func (mtp *MtpService) GetLocalDIDDocumentsByEmailHash(localLookups []*types.DIDLookup) (found []*did.Document, notFound []*types.DIDLookup, err error) {
	found = []*did.Document{}
	notFound = []*types.DIDLookup{}

	// resolve local lookups
	for _, lookup := range localLookups {
		mapping, mErr := getUserByScryptEmail(mtp.mappingRepo, lookup.EmailHash)
		if mErr != nil {
			if mErr == types.ErrNotFound {
				notFound = append(notFound, lookup)
				continue
			}
			global.Logger.Log("msg", "error while getting user by email", "err", mErr)
			return nil, nil, mErr
		}
		didDoc, dErr := mtp.ssiService.GetDIDDocument(mapping.MailioAddress)
		if dErr != nil {
			if dErr == types.ErrNotFound {
				notFound = append(notFound, lookup)
				continue
			}
			global.Logger.Log("msg", "error while resolving did", "err", dErr)
			return nil, nil, dErr
		}
		found = append(found, didDoc)
	}
	return found, notFound, nil
}

// FetchRemoteDID fetches DID documents for a list of email addresses with corresponding email hashes
func (mtp *MtpService) FetchRemoteDIDByEmailHash(userMailioAddress string, lookups map[string][]*types.DIDLookup) (found []*did.Document, notFound []*types.DIDLookup, err error) {

	found = []*did.Document{}
	notFound = []*types.DIDLookup{}

	// don't resolve the domain more than once for the same domain
	emailToResolvedEmailMapping := map[string]types.Domain{}
	// resolve domain from the lookups
	for emailDomain, lookup := range lookups {
		// check if domain is already resolved
		var resolvedDomain types.Domain
		if resolved, ok := emailToResolvedEmailMapping[emailDomain]; ok {
			resolvedDomain = resolved
		} else {
			rd, dErr := resolveDomain(mtp.domainRepo, emailDomain, false)
			if dErr != nil {
				if dErr == types.ErrNotFound {
					notFound = append(notFound, lookup...)
					continue
				}
				if dErr == types.ErrMxRecordCheckFailed {
					// do nothing (not interested in MX records)
				} else {
					global.Logger.Log("msg", "error while resolving domain", "err", dErr)
					return nil, nil, dErr
				}
			}
			emailToResolvedEmailMapping[emailDomain] = *rd
			resolvedDomain = *rd
		}
		// create handshake request objects signed by this server and request handshake from the domain
		request := &types.DIDDocumentSignedRequest{
			SenderDomain: global.Conf.Mailio.ServerDomain,
			DIDLookupRequest: types.DIDLookupRequest{
				SenderAddress: userMailioAddress,
				DIDLookups:    lookup,
				LookupHeader: types.LookupHeader{
					SignatureScheme:       types.Signature_Scheme_EdDSA_X25519,
					Timestamp:             time.Now().UnixMilli(),
					EmailLookupHashScheme: types.EmailLookupHashScheme_SC_N32768_R8_P1_L32_B64,
				},
			},
		}
		cborPayload, cErr := util.CborEncode(request.DIDLookupRequest)
		if cErr != nil {
			level.Error(global.Logger).Log("msg", "failed to cbor encode request", "err", cErr)
			return nil, nil, cErr
		}

		signature, sErr := util.Sign(cborPayload, global.PrivateKey)
		if sErr != nil {
			level.Error(global.Logger).Log("msg", "failed to sign request", "err", sErr)
			return nil, nil, sErr
		}
		request.CborPayloadBase64 = base64.StdEncoding.EncodeToString(cborPayload)
		request.SignatureBase64 = base64.StdEncoding.EncodeToString(signature)

		// send request to domain (API endpoint for DID documents: /api/v1/mtp/did)
		var signedResponse types.DIDDocumentSignedResponse
		response, rErr := mtp.restyClient.R().SetHeader("Content-Type", "application/json").
			SetBody(request).SetResult(&signedResponse).Post("https://" + resolvedDomain.Name + "/api/v1/mtp/did")
		if rErr != nil {
			level.Error(global.Logger).Log("msg", "failed to request DID document from remote server", "err", rErr)
			return nil, nil, rErr
		}
		if response.IsError() {
			level.Error(global.Logger).Log("msg", "error in did document response", "err", response.Error())
			return nil, nil, response.Error().(error)
		}
		rcborPayload, rcErr := base64.StdEncoding.DecodeString(signedResponse.CborPayloadBase64)
		rsignature, rsErr := base64.StdEncoding.DecodeString(signedResponse.SignatureBase64)
		if errors.Join(rcErr, rsErr) != nil {
			level.Error(global.Logger).Log("msg", "failed to decode cbor payload and signature responses", "err", errors.Join(rcErr, rsErr))
			return nil, nil, types.ErrSignatureInvalid
		}

		isValid, rsErr := util.Verify(rcborPayload, rsignature, resolvedDomain.MailioPublicKey)
		if rsErr != nil {
			level.Error(global.Logger).Log("msg", "failed to verify response", "err", rsErr)
			return nil, nil, types.ErrSignatureInvalid
		}
		if !isValid {
			level.Error(global.Logger).Log("msg", "failed to verify response", "err", "invalid signature")
			return nil, nil, types.ErrSignatureInvalid
		}

		foundRemoteDIDs := signedResponse.DIDLookupResponse.FoundDIDDocuments
		notFoundRemoteDIDs := signedResponse.DIDLookupResponse.NotFoundLookups

		found = append(found, foundRemoteDIDs...)
		notFound = append(notFound, notFoundRemoteDIDs...)
	}
	return found, notFound, nil
}
