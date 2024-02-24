package queue

import (
	"fmt"
	"strings"

	"github.com/hibiken/asynq"
	"github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
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
			mailioMessage.MTPStatusCodes = append(mailioMessage.MTPStatusCodes, &types.MTPStatusCode{
				Class:       5, // permanent failure
				Subject:     1, // address status
				Detail:      1, // bad destination address
				Description: fmt.Sprintf("failed to validate recipient %s", rec.Fragment()),
			})
			// next recipient validation
			continue
		}

		var result did.Document
		// check if local server (don't query it over network due to "rate limits")
		if rec.Value() == global.Conf.Host {
			r, rErr := msq.ssiService.GetDIDDocument(rec.Fragment())
			if rErr != nil {
				global.Logger.Log(rErr.Error(), "failed to validate recipient", rec.Fragment())
				mailioMessage.MTPStatusCodes = append(mailioMessage.MTPStatusCodes, &types.MTPStatusCode{
					Class:       5, // permanent failure
					Subject:     1, // address status
					Detail:      1, // bad destination address
					Description: fmt.Sprintf("failed to validate recipient %s", rec.Fragment()),
				})
				// next recipient validation
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
