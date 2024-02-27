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
func (msq *MessageQueue) validateRecipientDIDs(mailioMessage *types.MailioMessage, message *types.DIDCommMessage) map[string]did.Document {
	//validate recipients (checks if they are valid DIDs and if they are reachable via HTTP/HTTPS)
	recipientDidMap := map[string]did.Document{}
	for _, recipient := range message.To {
		rec, didErr := did.ParseDID(recipient)
		if didErr != nil {
			global.Logger.Log(didErr.Error(), "recipient verification failed", rec.Fragment())
			types.AppendMTPStatusCodeToMessage(mailioMessage, 5, 1, 1, fmt.Sprintf("failed to validate recipient %s", rec.Fragment()))
			continue
		}

		var result did.Document
		// check if local server (don't query it over network due to "rate limits")
		if rec.Value() == global.Conf.Host {
			r, rErr := msq.ssiService.GetDIDDocument(rec.Fragment())
			if rErr != nil {
				global.Logger.Log(rErr.Error(), "failed to validate recipient", rec.Fragment())
				types.AppendMTPStatusCodeToMessage(mailioMessage, 5, 1, 1, fmt.Sprintf("failed to validate recipient %s", rec.Fragment()))
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
				mailioMessage.MTPStatusCodes = append(mailioMessage.MTPStatusCodes, &mtpCode)
				// next recipient validation
				continue
			} else {
				result = *r
			}
		}
		recipientDidMap[rec.String()] = result
	}
	return recipientDidMap
}

// sign and httpSend DIDComm message
func (msq *MessageQueue) httpSend(message *types.DIDCommMessage,
	didDoc did.Document,
	endpoint string) (error, *types.MTPStatusCode) {
	// sign a DIDCommRequest
	request := &types.DIDCommRequest{
		DIDCommMessage:  message,
		SignatureScheme: types.Signature_Scheme_EdDSA_X25519,
		Timestamp:       time.Now().UnixMilli(),
	}
	cborPayload, cErr := util.CborEncode(request)
	if cErr != nil {
		level.Error(global.Logger).Log("msg", "failed to cbor encode request", "err", cErr)
		return fmt.Errorf("failed to cbor encode request: %v, %w", cErr, asynq.SkipRetry), nil
	}
	signature, sErr := util.Sign(cborPayload, global.PrivateKey)
	if sErr != nil {
		level.Error(global.Logger).Log("msg", "failed to sign request", "err", sErr)
		return fmt.Errorf("failed to sign request: %v, %w", sErr, asynq.SkipRetry), nil
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
		return types.ErrContinue, types.NewMTPStatusCode(5, 4, 4, fmt.Sprintf("failed to send message to %s", didDoc.ID.String()))
	}
	if response.IsError() {
		// if response.StatusCode() >= 405 && response.StatusCode() < 500 {
		// 	//TODO! should re-queue for later time?
		// } else {

		// }
		global.Logger.Log(response.String(), "failed to send message", endpoint)
		return types.ErrContinue, types.NewMTPStatusCode(4, 4, 4, fmt.Sprintf("failed to send message to %s", didDoc.ID.String()))
	}
	// validate response receipt
	responseId := responseResult.DIDCommRequest.DIDCommMessage.ID
	if responseId != message.ID {
		global.Logger.Log("response ID", responseId, "message ID", message.ID, "message ids don't match", endpoint)
		return types.ErrContinue, types.NewMTPStatusCode(5, 4, 4, fmt.Sprintf("failed to send message to %s", didDoc.ID.String()))
	}
	cbor, rcErr := base64.StdEncoding.DecodeString(responseResult.CborPayloadBase64)
	signature, rsErr := base64.StdEncoding.DecodeString(responseResult.SignatureBase64)
	if errors.Join(rcErr, rsErr) != nil {
		global.Logger.Log(errors.Join(cErr, sErr).Error(), "failed to decode cbor payload or signature")
		return types.ErrContinue, types.NewMTPStatusCode(5, 4, 4, fmt.Sprintf("failed to decode cbor or signature response from %s", didDoc.ID.String()))
	}

	// get public key from the recipients serv er
	discovery, dErr := msq.mtpService.ResolveDomain(endpoint, false)
	if dErr != nil {
		global.Logger.Log(dErr.Error(), "failed to get public key for", didDoc.ID.String())
		return types.ErrContinue, types.NewMTPStatusCode(5, 4, 4, fmt.Sprintf("failed to get public key for %s endpoint %s", didDoc.ID.String(), endpoint))
	}
	isValid, vErr := util.Verify(cbor, signature, discovery.MailioPublicKey)
	if vErr != nil {
		global.Logger.Log(vErr.Error(), "failed to verify response")
		return types.ErrContinue, types.NewMTPStatusCode(5, 4, 4, fmt.Sprintf("failed to verify response from %s", didDoc.ID.String()))
	}
	if !isValid {
		global.Logger.Log("response signature is invalid", "failed to verify response")
		// types.AppendMTPStatusCodeToMessage(mailioMessage, 5, 4, 4, fmt.Sprintf("failed to verify response from %s", didDoc.ID.String()))
		return types.ErrContinue, types.NewMTPStatusCode(5, 4, 4, fmt.Sprintf("failed to verify response from %s", didDoc.ID.String()))
	}
	return nil, nil
}

// handleReceivedDIDCommMessage handles received DIDComm messages
func (msq *MessageQueue) handleReceivedDIDCommMessage(message *types.DIDCommMessage) error {
	/**
	1. check if message with ID exists (if it does check if sent or if duplicate?)
	2. check if at least one recipient exists on this server and if it matches the recipient in the message (use DID domains i guess?)
	3. if everything checks out store message to intended recipients
	**/
	fromDID, fdErr := did.ParseDID(message.From)
	if fdErr != nil {
		//TODO: the sender cannot be validated, no retryies are allowed. Message fails permanently
		global.Logger.Log(fdErr.Error(), "failed to parse sender DID", message.From)
		return fmt.Errorf("failed to parse sender DID: %v: %w", fdErr, asynq.SkipRetry)
	}

	domain := fromDID.Value()
	resolvedDomain, rdErr := msq.mtpService.ResolveDomain(domain, false)
	if rdErr != nil {
		global.Logger.Log(rdErr.Error(), "failed retrieving Mailio DNS record", domain)
		return fmt.Errorf("failed retrieving Mailio DNS record: %v: %w", rdErr, asynq.SkipRetry)
	}
	serverDID, didErr := msq.mtpService.GetServerDIDDocument(resolvedDomain.Name)
	if didErr != nil {
		global.Logger.Log(didErr.Error(), "failed retrieving Mailio DID document", domain)
		return fmt.Errorf("failed retrieving Mailio DID document: %v: %w", didErr, asynq.SkipRetry)
	}
	endpoint := msq.extractDIDMessageEndpoint(serverDID)
	if endpoint == "" {
		// Bad destination address syntax
		return fmt.Errorf("unable to route message to %s for %s: %w", endpoint, serverDID.ID.String(), asynq.SkipRetry)
	}

	localRecipientsAddresses := []string{}
	for _, recipient := range message.EncryptedBody.Recipients {
		recAddress := recipient.Header.Kid
		parsedDid, pErr := did.ParseDID(recAddress)
		if pErr != nil {
			// skip if parsing fails
			global.Logger.Log(pErr.Error(), "failed to parse recipient DID", recAddress)
			continue
		}
		if parsedDid.Value() == global.Conf.Mailio.Domain {
			localRecipientsAddresses = append(localRecipientsAddresses, parsedDid.Fragment())
		}
	}
	thisServerDIDDoc, err := util.CreateMailioDIDDocument()
	if err != nil {
		global.Logger.Log(err.Error(), "failed to create Mailio DID document")
		return fmt.Errorf("failed to create Mailio DID document: %v: %w", err, asynq.SkipRetry)
	}
	if len(localRecipientsAddresses) == 0 {
		// TODO: Handle the case when there are no local recipients.
		// TODO: send error message to sender that empty recipients
		deliveryMsg := &types.PlainBodyDelivery{
			StatusCodes: []*types.MTPStatusCode{
				{
					Class:       5,
					Subject:     4,
					Detail:      4,
					Description: "no local recipients",
				},
			},
		}
		deliveryMsgStr, delErr := json.Marshal(deliveryMsg)
		if delErr != nil {
			global.Logger.Log(delErr.Error(), "failed to marshal delivery message")
			return fmt.Errorf("failed to marshal delivery message: %v: %w", delErr, asynq.SkipRetry)
		}
		didMessage := &types.DIDCommMessage{
			ID:              message.ID,
			Intent:          types.DIDCommIntentDelivery,
			Type:            "application/didcomm-signed+json",
			From:            "did:web:" + global.Conf.Host + ":" + thisServerDIDDoc.ID.Value(), // this server DID
			To:              []string{message.From},
			PlainBodyBase64: base64.StdEncoding.EncodeToString(deliveryMsgStr),
		}
		sndErr, sndCode := msq.httpSend(didMessage, *serverDID, endpoint)
		if sndErr != nil {
			global.Logger.Log(sndErr.Error(), "failed to send message to sender", sndCode.Class, sndCode.Subject, sndCode.Detail, sndCode.Description, sndCode.Address)
			return fmt.Errorf("failed to send message to sender: %v: %w", sndErr, asynq.SkipRetry)
		}
	}
	successfullDelivery := []*types.MTPStatusCode{}
	for _, recAddress := range localRecipientsAddresses {
		// store message in database (received folder of the recipient)
		mailioMessage := &types.MailioMessage{
			BaseDocument: types.BaseDocument{
				ID: message.ID,
			},
			ID:             message.ID,
			DIDCommMessage: message,
			Folder:         types.MailioFolderInbox, // TODO!: based on the recipient's settings
			Created:        time.Now().UnixMilli(),
			MTPStatusCodes: []*types.MTPStatusCode{
				{
					Class:   2,
					Subject: 0,
					Detail:  0,
				},
			},
		}
		_, sErr := msq.userService.SaveMessage(recAddress, mailioMessage)
		if sErr != nil {
			global.Logger.Log(sErr.Error(), "failed to save message", recAddress)
			// send error message to sender
			successfullDelivery = append(successfullDelivery, &types.MTPStatusCode{
				Class:       5,
				Subject:     4,
				Detail:      4,
				Description: fmt.Sprintf("failed to save message for %s", recAddress),
				Address:     recAddress,
			})
		} else {
			successfullDelivery = append(successfullDelivery, &types.MTPStatusCode{
				Class:       2,
				Subject:     0,
				Detail:      0,
				Description: fmt.Sprintf("message received by %s", recAddress),
				Address:     recAddress,
			})
		}
	}
	//TODO: send delivery message to sender
	deliveryMsg := &types.PlainBodyDelivery{
		StatusCodes: successfullDelivery,
	}
	deliveryMsgStr, delErr := json.Marshal(deliveryMsg)
	if delErr != nil {
		global.Logger.Log(delErr.Error(), "failed to marshal delivery message")
		return fmt.Errorf("failed to marshal delivery message: %v: %w", delErr, asynq.SkipRetry)
	}
	didMessage := &types.DIDCommMessage{
		ID:              message.ID,
		Intent:          types.DIDCommIntentDelivery,
		Type:            "application/didcomm-signed+json",
		From:            "did:web:" + global.Conf.Host + ":" + thisServerDIDDoc.ID.Value(), // this server DID
		To:              []string{message.From},
		PlainBodyBase64: base64.StdEncoding.EncodeToString(deliveryMsgStr),
	}
	sndErr, sndCode := msq.httpSend(didMessage, *serverDID, endpoint)
	if sndErr != nil {
		global.Logger.Log(sndErr.Error(), "failed to send message to sender", sndCode.Class, sndCode.Subject, sndCode.Detail, sndCode.Description, sndCode.Address)
		return fmt.Errorf("failed to send message to sender: %v: %w", sndErr, asynq.SkipRetry)
	}
	return nil
}
