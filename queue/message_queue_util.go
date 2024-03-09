package queue

import (
	"encoding/base64"
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

// Extracts the message endpoint from DID document
// in case localhost/127.0.0.1 schema is http, otherwise default schema is https
func (msq *MessageQueue) extractDIDMessageEndpoint(didDoc *did.Document) string {
	// find a service endpoint for a recipient from DID Document
	endpoint := ""
	for _, service := range didDoc.Service {
		if service.Type == "DIDCommMessaging" {
			endpoint = strings.TrimSuffix(service.ServiceEndpoint, "/")
			scheme := "https"
			if !strings.HasPrefix(endpoint, "http") {
				if strings.Contains(endpoint, "localhost") || strings.Contains(endpoint, "127.0.0.1") {
					scheme = "http"
				}
				endpoint = fmt.Sprintf("%s://%s", scheme, endpoint)
			}
			break
		}
	}
	return endpoint
}

// validates senders DID Docxument (if it matches the From field)
func (msq *MessageQueue) validateSenderDID(message *types.DIDCommMessage, userAddress string) (*did.DID, error) {
	senderDid, sdidErr := msq.ssiService.GetDIDDocument(userAddress)
	if sdidErr != nil {
		global.Logger.Log(sdidErr.Error(), "failed to retrieve did document", userAddress)
		return nil, fmt.Errorf("failed to retrieve DID document: %v: %w", sdidErr, asynq.SkipRetry)
	}

	fromDID, didErr := did.ParseDID(message.From)
	if didErr != nil {
		global.Logger.Log(didErr.Error(), "sender verification failed")
		return nil, fmt.Errorf("failed to retrieve DID document: %v: %w", didErr, asynq.SkipRetry)
	}

	// addresses from and logged in users must match
	if fromDID.Fragment() != senderDid.ID.Value() {
		return nil, fmt.Errorf("from field invalid: %v: %w", sdidErr, asynq.SkipRetry)
	}
	return &fromDID, nil
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
			mtpStatusErrors = append(mtpStatusErrors, types.NewMTPStatusCode(5, 1, 1, fmt.Sprintf("failed to validate recipient", types.WithRecAddress(rec.Fragment()))))
			continue
		}

		var result did.Document
		// check if local server (don't query it over network due to "rate limits")
		host := global.Conf.Host
		if global.Conf.Port != 0 {
			host += ":" + fmt.Sprintf("%d", global.Conf.Port)
		}
		if rec.Value() == host {
			r, rErr := msq.ssiService.GetDIDDocument(rec.Fragment())
			if rErr != nil {
				global.Logger.Log(rErr.Error(), "failed to validate recipient", rec.Fragment())
				mtpStatusErrors = append(mtpStatusErrors, types.NewMTPStatusCode(5, 1, 1, fmt.Sprintf("failed to validate recipient", types.WithRecAddress(rec.Fragment()))))
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
		SenderDomain:      global.Conf.Host,
	}

	var responseResult types.DIDCommSignedRequest

	response, rErr := msq.restyClient.R().SetBody(signedRequest).SetResult(&responseResult).Post(endpoint)
	if rErr != nil {
		global.Logger.Log(rErr.Error(), "failed to send message", endpoint)
		return types.NewMTPStatusCode(5, 4, 4, fmt.Sprintf("failed to send message")), types.ErrContinue
	}
	if response.IsError() {
		// if response.StatusCode() >= 405 && response.StatusCode() < 500 {
		// 	//TODO! should re-queue for later time?
		// } else {

		// }
		global.Logger.Log(response.String(), "failed to send message", endpoint, "code", response.StatusCode(), "body", string(response.Body()))
		return types.NewMTPStatusCode(4, 4, 4, fmt.Sprintf("failed to send message")), types.ErrContinue
	}
	// validate response receipt
	responseId := responseResult.DIDCommRequest.DIDCommMessage.ID
	if responseId != message.ID {
		global.Logger.Log("response ID", responseId, "message ID", message.ID, "message ids don't match", endpoint)
		return types.NewMTPStatusCode(5, 4, 4, fmt.Sprintf("failed to send message")), types.ErrContinue
	}
	cbor, rcErr := base64.StdEncoding.DecodeString(responseResult.CborPayloadBase64)
	signature, rsErr := base64.StdEncoding.DecodeString(responseResult.SignatureBase64)
	if errors.Join(rcErr, rsErr) != nil {
		global.Logger.Log(errors.Join(cErr, sErr).Error(), "failed to decode cbor payload or signature")
		return types.NewMTPStatusCode(5, 4, 4, fmt.Sprintf("failed to decode cbor or signature response from %s", endpoint)), types.ErrContinue
	}

	// get public key from the recipients serv er
	discovery, dErr := msq.mtpService.ResolveDomain(endpoint, false)
	if dErr != nil {
		global.Logger.Log(dErr.Error(), "failed to get public key for", endpoint)
		return types.NewMTPStatusCode(5, 4, 4, fmt.Sprintf("failed to get public key for endpoint %s", endpoint)), types.ErrContinue
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

// checks if user already recieved a message with given messageID
func (msq *MessageQueue) hasAlreadyReceivedMessage(messageID string, did did.DID) bool {
	userAddress := did.Fragment()
	if userAddress == "" {
		userAddress = did.Value()
	}
	if userAddress == "" {
		global.Logger.Log("user address is empty", "failed to check if message exists", did.String())
		return true
	}

	// msg, exErr := msq.userService.GetMessage(userAddress, messageID)
	// if exErr != nil {
	// 	if exErr != types.ErrNotFound {
	// 		global.Logger.Log(exErr.Error(), "failed to check if message exists", userAddress)
	// 		return false
	// 	} else if exErr == types.ErrNotFound {
	// 		return false
	// 	}
	// }
	// // received messages must not be in sent folder
	// if msg != nil && msg.Folder == types.MailioFolderSent {
	// 	return false
	// }
	return true
}
