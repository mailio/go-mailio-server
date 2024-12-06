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
	domainRepo  repository.Repository
	mappingRepo repository.Repository
	userRepo    repository.Repository
	restyClient *resty.Client
	ssiService  *SelfSovereignService
}

func NewMtpService(dbSelector repository.DBSelector, env *types.Environment) *MtpService {
	domainRepo, err := dbSelector.ChooseDB(repository.Domain)
	if err != nil {
		level.Error(global.Logger).Log("msg", "error while choosing db", "err", err)
		panic(err)
	}
	mappingRepo, err := dbSelector.ChooseDB(repository.MailioMapping)
	if err != nil {
		level.Error(global.Logger).Log("msg", "error while choosing db", "err", err)
		panic(err)
	}
	userRepo, err := dbSelector.ChooseDB(repository.User)
	if err != nil {
		level.Error(global.Logger).Log("msg", "error while choosing db", "err", err)
		panic(err)
	}
	ssiService := NewSelfSovereignService(dbSelector, env)
	restyClient := resty.New().SetRetryCount(3).SetRetryWaitTime(5 * time.Second)
	return &MtpService{domainRepo: domainRepo, mappingRepo: mappingRepo, userRepo: userRepo, ssiService: ssiService, restyClient: restyClient}
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
		var shake *types.Handshake
		var err error

		switch {
		case lookup.ID != "":
			shake, err = GetHandshakeByID(mtp.userRepo, lookup.Address, lookup.ID)
		case lookup.Address != "":
			shake, err = GetHandshakeByMailioAddress(mtp.userRepo, lookup.Address, senderAddress)
		case lookup.EmailHash != "":
			mappedUser, userErr := getUserByScryptEmail(mtp.userRepo, lookup.EmailHash)
			if userErr != nil {
				err = userErr
				break
			}
			shake, err = GetHandshakeByMailioAddress(mtp.userRepo, mappedUser.MailioAddress, senderAddress)
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
func (mtp *MtpService) FetchDIDDocuments(userMailioAddress string, didLookups []*types.DIDLookup) (found []*types.DIDLookup, notFound []*types.DIDLookup, err error) {
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
func (mtp *MtpService) GetLocalDIDDocumentsByEmailHash(localLookups []*types.DIDLookup) (found []*types.DIDLookup, notFound []*types.DIDLookup, err error) {
	found = []*types.DIDLookup{}
	notFound = []*types.DIDLookup{}

	// resolve local lookups
	for _, lookup := range localLookups {
		mapping, mErr := getUserByScryptEmail(mtp.mappingRepo, lookup.EmailHash)
		if mErr != nil {
			if mErr == types.ErrNotFound {
				notFound = append(notFound, lookup)
				continue
			}
			handleDIDLookupError(mErr,
				*types.NewMTPStatusCode(types.ClassCodePermFailure, types.SubjectCodeMailSystem, 0, "local: error while getting user by email"),
				found,
				&notFound)
			continue
		}
		didDoc, dErr := mtp.ssiService.GetDIDDocument(mapping.MailioAddress)
		if dErr != nil {
			if dErr == types.ErrNotFound {
				notFound = append(notFound, lookup)
				continue
			}
			handleDIDLookupError(dErr,
				*types.NewMTPStatusCode(types.ClassCodePermFailure, types.SubjectCodeMailSystem, 0, "local: error while resolving did"),
				found,
				&notFound)
			continue
		}
		lookup.DIDDocument = didDoc
		lookup.SupportsMailio = true                                    // local server supports mailio
		lookup.SupportsStandardEmail = len(global.Conf.SmtpServers) > 0 // local server supports standard email

		found = append(found, lookup)
	}
	return found, notFound, nil
}

func handleDIDLookupError(
	err error,
	errorCode types.MTPStatusCode,
	lookup []*types.DIDLookup,
	notFound *[]*types.DIDLookup,
) {
	level.Error(global.Logger).Log("msg", errorCode.Description, "err", err)
	for _, l := range lookup {
		l.MTPStatusCode = &errorCode
	}
	*notFound = append(*notFound, lookup...)
}

// FetchRemoteDID fetches DID documents for a list of email addresses with corresponding email hashes
// Returns a list of found DID documents and a list of not found email addresses
// userMailioAddress string requesting user
// lookups map[string][]*types.DIDLookup email domain to list of lookups
// notFound array is filled out when remote server returns code >= 400
func (mtp *MtpService) FetchRemoteDIDByEmailHash(userMailioAddress string, lookups map[string][]*types.DIDLookup) (found []*types.DIDLookup, notFound []*types.DIDLookup, err error) {

	found = []*types.DIDLookup{}
	notFound = []*types.DIDLookup{}

	// resolve each domain once only
	emailToResolvedEmailMapping := map[string]*types.Domain{}
	// resolve domain from the lookups
	for emailDomain, lookup := range lookups {
		// check if domain is already resolved
		var resolvedDomain types.Domain
		if resolved, ok := emailToResolvedEmailMapping[emailDomain]; ok {
			emailToResolvedEmailMapping[emailDomain] = resolved
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
					handleDIDLookupError(dErr,
						*types.NewMTPStatusCode(types.ClassCodePermFailure, types.SubjectCodeNetwork, 3, "error while resolving domain"),
						lookup,
						&notFound)
					continue
				}
			}
			emailToResolvedEmailMapping[emailDomain] = rd
			resolvedDomain = *rd
		}

		if !resolvedDomain.SupportsMailio && resolvedDomain.SupportsStandardEmails {
			// smtp domain resolved
			for _, l := range lookup {
				l.SupportsStandardEmail = true
				l.SupportsMailio = false
			}
			found = append(found, lookup...)
			continue
		}
		if !resolvedDomain.SupportsMailio && !resolvedDomain.SupportsStandardEmails {
			for _, l := range lookup {
				l.SupportsMailio = false
				l.SupportsStandardEmail = false
				l.MTPStatusCode = types.NewMTPStatusCode(types.ClassCodePermFailure, types.SubjectCodeMailSystem, 0, "domain does not support mailio or standard email")
			}
			notFound = append(notFound, lookup...)
			continue
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
			handleDIDLookupError(cErr,
				*types.NewMTPStatusCode(types.ClassCodePermFailure, types.SubjectMessageContent, 0, "failed to cbor encode request"),
				lookup,
				&notFound)
			continue
		}

		signature, sErr := util.Sign(cborPayload, global.PrivateKey)
		if sErr != nil {
			handleDIDLookupError(cErr,
				*types.NewMTPStatusCode(types.ClassCodePermFailure, types.SubjectSecurity, 5, "failed to sign request"),
				lookup,
				&notFound)
			continue
		}
		request.CborPayloadBase64 = base64.StdEncoding.EncodeToString(cborPayload)
		request.SignatureBase64 = base64.StdEncoding.EncodeToString(signature)

		// send request to domain (API endpoint for DID documents: /api/v1/mtp/did)
		var signedResponse types.DIDDocumentSignedResponse
		response, rErr := mtp.restyClient.R().SetHeader("Content-Type", "application/json").
			SetBody(request).SetResult(&signedResponse).Post("https://" + resolvedDomain.Name + "/api/v1/mtp/did")
		if rErr != nil {
			handleDIDLookupError(rErr,
				*types.NewMTPStatusCode(types.ClassCodeTempFailure, types.SubjectCodeNetwork, 1, "failed to request DID document from remote server"),
				lookup,
				&notFound)
			continue
		}
		if response.IsError() {
			if response.StatusCode() >= 400 {
				handleDIDLookupError(rErr,
					*types.NewMTPStatusCode(types.ClassCodeTempFailure, types.SubjectCodeNetwork, 0, "received error from remote server: "+resolvedDomain.Name),
					lookup,
					&notFound)
				continue
			}
			if response.StatusCode() == 404 {
				handleDIDLookupError(errors.New("DID not found"),
					*types.NewMTPStatusCode(types.ClassCodePermFailure, types.SubjectCodeNetwork, 0, "API not found on remote server: "+resolvedDomain.Name),
					lookup,
					&notFound)
				continue
			}
			if response.StatusCode() == 429 {
				handleDIDLookupError(errors.New("rate limit exceeded"),
					*types.NewMTPStatusCode(types.ClassCodeTempFailure, types.SubjectCodeNetwork, 5, "rate limit exceeded: "+resolvedDomain.Name),
					lookup,
					&notFound)
				continue
			}
			handleDIDLookupError(errors.New("unknown network error"),
				*types.NewMTPStatusCode(types.ClassCodePermFailure, types.SubjectCodeNetwork, 0, "unkown network error: "+resolvedDomain.Name),
				lookup,
				&notFound)
			continue
		}
		rcborPayload, rcErr := base64.StdEncoding.DecodeString(signedResponse.CborPayloadBase64)
		rsignature, rsErr := base64.StdEncoding.DecodeString(signedResponse.SignatureBase64)
		if errors.Join(rcErr, rsErr) != nil {
			handleDIDLookupError(errors.Join(rcErr, rsErr),
				*types.NewMTPStatusCode(types.ClassCodePermFailure, types.SubjectMessageContent, 5, "failed to decode cbor payload and signature responses"),
				lookup,
				&notFound)
			continue
		}

		isValid, rsErr := util.Verify(rcborPayload, rsignature, resolvedDomain.MailioPublicKey)
		if rsErr != nil {
			handleDIDLookupError(rsErr,
				*types.NewMTPStatusCode(types.ClassCodePermFailure, types.SubjectSecurity, 7, "failed to verify response signature"),
				lookup,
				&notFound)
			continue
		}
		if !isValid {
			handleDIDLookupError(errors.New("invalid signature"),
				*types.NewMTPStatusCode(types.ClassCodePermFailure, types.SubjectSecurity, 7, "invalid signature"),
				lookup,
				&notFound)
			continue
		}

		foundRemoteDIDs := signedResponse.DIDLookupResponse.FoundLookups
		notFoundRemoteDIDs := signedResponse.DIDLookupResponse.NotFoundLookups

		// found remote DID documents add info about domain resolution
		for _, foundRD := range foundRemoteDIDs {
			foundRD.SupportsMailio = resolvedDomain.SupportsMailio
			foundRD.SupportsStandardEmail = resolvedDomain.SupportsStandardEmails
		}
		for _, notFoundRD := range notFoundRemoteDIDs {
			notFoundRD.SupportsMailio = resolvedDomain.SupportsMailio
			notFoundRD.SupportsStandardEmail = resolvedDomain.SupportsStandardEmails
		}

		found = append(found, foundRemoteDIDs...)
		notFound = append(notFound, notFoundRemoteDIDs...)
	}
	return found, notFound, nil
}
