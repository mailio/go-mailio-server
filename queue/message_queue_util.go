package queue

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-kit/log/level"
	"github.com/hibiken/asynq"
	"github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

// validateRecipientDIDFromEmails validates the recipient DIDs from emails and collect valid DIDs in a recipientDidMap
// this is alternative to validateRecipientDIDs (which requires To field to have all DIDs)
func (msq *MessageQueue) validateRecipientDIDFromEmails(message *types.DIDCommMessage) (map[string]did.Document, []*types.MTPStatusCode) {
	//validate recipients (checks if they are valid DIDs and if they are reachable via HTTP/HTTPS)
	mtpStatusErrors := []*types.MTPStatusCode{}
	recipientDidMap := map[string]did.Document{}

	// create lookups list
	lookups := []*types.DIDLookup{}
	for _, recipientEmail := range message.ToEmails {
		lookup := &types.DIDLookup{
			Email:     recipientEmail.Email,
			EmailHash: recipientEmail.EmailHash,
		}
		lookups = append(lookups, lookup)
	}
	hasinvalidEmail := false
	found, notFound, err := msq.mtpService.FetchDIDDocuments(message.From, lookups)
	if err != nil {
		if err == types.ErrInvalidEmail { // should not happen
			mtpStatusErrors = append(mtpStatusErrors, types.NewMTPStatusCode(5, 1, 1, "one of the recipients has invalid email"))
			hasinvalidEmail = true
		}
	}
	if hasinvalidEmail {
		return nil, mtpStatusErrors
	}

	for _, notFoundRecipient := range notFound {
		mtpStatusErrors = append(mtpStatusErrors, types.NewMTPStatusCode(5, 1, 1, fmt.Sprintf("recipient not found: %s", notFoundRecipient.Email)))
	}

	for _, recipient := range found {
		didDoc := recipient.DIDDocument
		rec := didDoc.ID
		recipientDidMap[rec.String()] = *recipient.DIDDocument
	}

	return recipientDidMap, mtpStatusErrors
}

// validateRecipientDid validates the recipient DIDs and collect valid DIDs in a recipientDidMap
// invalid recipients are added to MailioMessage as MTPStatusCodes
func (msq *MessageQueue) validateRecipientDIDs(message *types.DIDCommMessage) (map[string]did.Document, []*types.MTPStatusCode) {
	//validate recipients (checks if they are valid DIDs and if they are reachable via HTTP/HTTPS)
	recipientDidMap := map[string]did.Document{}

	mtpStatusErrors := []*types.MTPStatusCode{}

	for _, recipient := range message.To {
		rec, didErr := did.ParseDID(recipient)
		if didErr != nil {
			global.Logger.Log(didErr.Error(), "recipient verification failed", rec.Fragment())
			mtpStatusErrors = append(mtpStatusErrors, types.NewMTPStatusCode(5, 1, 1, "failed to validate recipient", types.WithRecAddress(rec.Fragment())))
			continue
		}

		var result did.Document
		// check if local server (don't query it over network due to "rate limits")
		host := global.Conf.Mailio.ServerDomain
		if rec.Value() == host {
			r, rErr := msq.ssiService.GetDIDDocument(rec.Fragment())
			if rErr != nil {
				global.Logger.Log(rErr.Error(), "failed to validate recipient", rec.Fragment())
				mtpStatusErrors = append(mtpStatusErrors, types.NewMTPStatusCode(5, 1, 1, "failed to validate recipient", types.WithRecAddress(rec.Fragment())))
				continue
			} else {
				result = *r
			}
		} else {
			// remote fetch did
			r, rErr := msq.ssiService.FetchRemoteDID(&rec)
			if rErr != nil {
				global.Logger.Log(rErr.Error(), "failed to validate remote recipient", rec.Fragment())
				mtpCode := types.MTPStatusCode{}
				switch rErr {
				case types.ErrNotFound:
					mtpCode.Class = 5   // permanent failure
					mtpCode.Subject = 1 // address status
					mtpCode.Detail = 1  // bad destination address
					mtpCode.Description = fmt.Sprintf("recipient not found: %s", rec.Fragment())
				case types.ErrBadRequest:
					mtpCode.Class = 5   // permanent failure
					mtpCode.Subject = 4 // network and routing status
					mtpCode.Detail = 4  // unable to route
					mtpCode.Description = fmt.Sprintf("error response from destination server: %s", rec.Fragment())
				case types.ErrConflict: // rate limit exceeded
					//TODO should re-queue for later time?
					mtpCode.Class = 4   // temporary failure
					mtpCode.Subject = 4 // network and routing status
					mtpCode.Detail = 5  // mail system congestion
					mtpCode.Description = fmt.Sprintf("rate limit exceeded for destination server: %s", rec.Fragment())
				default:
					mtpCode.Class = 5   // permanent failure
					mtpCode.Subject = 0 // unknown
					mtpCode.Detail = 0  // unknown
					mtpCode.Description = fmt.Sprintf("unknown error for destination server: %s", rec.Fragment())
				}
				mtpStatusErrors = append(mtpStatusErrors, &mtpCode)
				// next recipient validation
				continue
			} else {
				result = *r
			}
		}
		recipientDidMap[rec.String()] = result
	}
	return recipientDidMap, mtpStatusErrors
}

// sign and httpSend DIDComm message
func (msq *MessageQueue) httpSend(message *types.DIDCommMessage,
	endpoint string) (*types.MTPStatusCode, error) {
	// sign a DIDCommRequest
	request := &types.DIDCommRequest{
		DIDCommMessage:  message,
		SignatureScheme: types.Signature_Scheme_EdDSA_X25519,
		Timestamp:       time.Now().UnixMilli(),
	}
	cborPayload, cErr := util.CborEncode(request)
	if cErr != nil {
		level.Error(global.Logger).Log("msg", "failed to cbor encode request", "err", cErr)
		return nil, fmt.Errorf("failed to cbor encode request: %v, %w", cErr, asynq.SkipRetry)
	}

	signature, sErr := util.Sign(cborPayload, global.PrivateKey)
	if sErr != nil {
		level.Error(global.Logger).Log("msg", "failed to sign request", "err", sErr)
		return nil, fmt.Errorf("failed to sign request: %v, %w", sErr, asynq.SkipRetry)
	}

	signedRequest := &types.DIDCommSignedRequest{
		DIDCommRequest:    request,
		CborPayloadBase64: base64.StdEncoding.EncodeToString(cborPayload),
		SignatureBase64:   base64.StdEncoding.EncodeToString(signature),
		SenderDomain:      global.Conf.Mailio.ServerDomain,
	}

	var responseResult types.DIDCommSignedRequest

	response, rErr := msq.restyClient.R().SetBody(signedRequest).SetResult(&responseResult).Post(endpoint)
	if rErr != nil {
		global.Logger.Log(rErr.Error(), "failed to send message", endpoint)
		return types.NewMTPStatusCode(5, 4, 4, "failed to send message"), types.ErrContinue
	}
	if response.IsError() {
		// if response.StatusCode() >= 405 && response.StatusCode() < 500 {
		// 	//TODO! should re-queue for later time?
		// } else {

		// }
		global.Logger.Log(response.String(), "failed to send message", endpoint, "code", response.StatusCode(), "body", string(response.Body()))
		return types.NewMTPStatusCode(4, 4, 4, "failed to send message"), types.ErrContinue
	}
	// validate response receipt
	responseId := responseResult.DIDCommRequest.DIDCommMessage.ID
	if responseId != message.ID {
		global.Logger.Log("response ID", responseId, "message ID", message.ID, "message ids don't match", endpoint)
		return types.NewMTPStatusCode(5, 4, 4, "failed to send message"), types.ErrContinue
	}
	cbor, rcErr := base64.StdEncoding.DecodeString(responseResult.CborPayloadBase64)
	signature, rsErr := base64.StdEncoding.DecodeString(responseResult.SignatureBase64)
	if errors.Join(rcErr, rsErr) != nil {
		global.Logger.Log(errors.Join(cErr, sErr).Error(), "failed to decode cbor payload or signature")
		return types.NewMTPStatusCode(5, 4, 4, fmt.Sprintf("failed to decode cbor or signature response from %s", endpoint)), types.ErrContinue
	}

	// get public key from the recipients serv er
	discovery := &types.Domain{SupportsMailio: true, MailioPublicKey: base64.StdEncoding.EncodeToString(global.PublicKey)}
	if !strings.Contains(endpoint, "localhost") {
		d, dErr := msq.mtpService.ResolveDomain(endpoint, false)
		if dErr != nil {
			global.Logger.Log(dErr.Error(), "failed to get public key for", endpoint)
			return types.NewMTPStatusCode(5, 4, 4, fmt.Sprintf("failed to get public key for endpoint %s", endpoint)), types.ErrContinue
		}
		discovery = d
	}
	isValid, vErr := util.Verify(cbor, signature, discovery.MailioPublicKey)
	if vErr != nil {
		global.Logger.Log(vErr.Error(), "failed to verify response")
		return types.NewMTPStatusCode(5, 4, 4, fmt.Sprintf("failed to verify response from %s", endpoint)), types.ErrContinue
	}
	if !isValid {
		global.Logger.Log("response signature is invalid", "failed to verify response")
		return types.NewMTPStatusCode(5, 4, 4, fmt.Sprintf("failed to verify response from %s", endpoint)), types.ErrContinue
	}
	return nil, nil
}

func (msq *MessageQueue) isNonceValid(nonceBase64Object string) bool {
	// check if nonce is valid
	if nonceBase64Object == "" {
		return false
	}

	nonceBody, nErr := base64.StdEncoding.DecodeString(nonceBase64Object)
	nonceMap := map[string]string{}
	nuErr := json.Unmarshal(nonceBody, &nonceMap)
	if nErr != nil || nuErr != nil {
		return false
	}
	if _, ok := nonceMap["nonce"]; !ok {
		return false
	}
	nonceString := nonceMap["nonce"]
	if len([]byte(nonceString)) != 16 {
		return false
	}

	nc, err := msq.nonceService.GetNonce(nonceMap["nonce"])
	if err != nil {
		return false
	}
	if nc == nil {
		return false
	}
	return true
}
