package services

import (
	"encoding/base64"
	"errors"
	"fmt"
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
	restyClient   *resty.Client
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
	restyClient := resty.New().SetRetryCount(3).SetRetryWaitTime(5 * time.Second)
	return &MtpService{domainRepo: domainRepo, handshakeRepo: handshakeRepo, restyClient: restyClient}
}

// Lookup handshakes locally and if not found
// then request from remote servers
func (mtp *MtpService) LookupHandshakes(senderAddress string, inputLookups []types.HandshakeLookup) ([]*types.HandshakeContent, error) {

	// first check if we have the handshakes in the local database
	found, notFound, err := mtp.LocalHandshakeLookup(senderAddress, inputLookups)
	if err != nil {
		return nil, err
	}

	// group by domain name (destination server) of the not locally found handshakes
	remoteLookups := map[string][]types.HandshakeLookup{}
	for _, lookup := range notFound {
		domain := lookup.OriginSever.Domain
		if _, ok := remoteLookups[domain]; !ok {
			remoteLookups[domain] = []types.HandshakeLookup{}
		}
		remoteLookups[domain] = append(remoteLookups[domain], lookup)
	}
	for domain, handshakeLookups := range remoteLookups {
		domainResults, dErr := mtp.requestHandshakeFromRemoteServer(senderAddress, handshakeLookups, domain)
		if dErr != nil {
			return nil, dErr
		}
		for _, domainHandshakes := range domainResults {
			handshakes := domainHandshakes.HandshakeResponse.Handshakes
			found = append(found, handshakes...)
		}
	}
	return found, nil
}

// Request handshake from remote server calling /api/v1/mtp/handshake endpoint
// returns list of handshakes signed by the remote server
// if handshake older than 24 hours - it will not be returned

func (mtp *MtpService) requestHandshakeFromRemoteServer(senderAddress string, handshakeLookups []types.HandshakeLookup, domain string) ([]types.HandshakeSignedResponse, error) {
	output := []types.HandshakeSignedResponse{}

	domainObject, resErr := resolveDomain(mtp.domainRepo, domain, false)
	if resErr != nil {
		return nil, resErr
	}
	if len(handshakeLookups) == 0 {
		return nil, types.ErrBadRequest
	}
	// create handshake request objects signed by this server and request handshake from the domain
	request := &types.HandshakeSignedRequest{
		SenderDomain: global.Conf.Host,
		HandshakeRequest: types.HandshakeRequest{
			SenderAddress:                senderAddress,
			ReturnDefaultServerHandshake: true,
			HandshakeLookups:             handshakeLookups,
			HandshakeHeader: types.HandshakeHeader{
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
// if handshake older than 24 hours - it will not be returned
func (mtp *MtpService) LocalHandshakeLookup(senderAddress string, lookups []types.HandshakeLookup) (found []*types.HandshakeContent, notFound []types.HandshakeLookup, outputErr error) {

	found = []*types.HandshakeContent{}
	notFound = []types.HandshakeLookup{}

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
				notFound = append(notFound, lookup)
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
