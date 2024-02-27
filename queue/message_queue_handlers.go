package queue

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
	"github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

// handleReceivedDIDCommMessage handles received DIDComm messages
func (msq *MessageQueue) handleReceivedDIDCommMessage(message *types.DIDCommMessage) error {
	/**
	1. Get the senders DID document to extract the service endpoint
	2. Check if the message already exists in the local database (it shouldn't exist but if it does, add MTP codes to it)
	3. Check if at least one recipient exists on this server and if it matches the recipient in the message
	3. if everything checks out store message to intended recipients and send confirmation back
	**/

	// get the senders DID and get the service endpoint where message was sent from
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
	thisServerDIDDoc, err := util.CreateMailioDIDDocument()
	if err != nil {
		global.Logger.Log(err.Error(), "failed to create Mailio DID document")
		return fmt.Errorf("failed to create Mailio DID document: %v: %w", err, asynq.SkipRetry)
	}

	// collect local recipients of the message
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

	deliveryStatuses := []*types.MTPStatusCode{}
	if len(localRecipientsAddresses) == 0 {
		// Handles the case when there are no local recipients.
		deliveryStatuses = append(deliveryStatuses, types.NewMTPStatusCode(5, 4, 4, "no local recipients found"))
	}

	for _, recAddress := range localRecipientsAddresses {
		// store message in database (received folder of the recipient)
		mailioMessage, err := msq.userService.GetMessage(recAddress, message.ID)
		if err != nil && err != types.ErrNotFound {
			global.Logger.Log(err.Error(), "failed to get message", recAddress)
			// send error message to sender
			deliveryStatuses = append(deliveryStatuses, types.NewMTPStatusCode(4, 5, 1, fmt.Sprintf("duplicate message ID %s", message.ID), types.WithRecAddress(recAddress)))
			continue
		}
		if mailioMessage == nil {
			mailioMessage = &types.MailioMessage{
				BaseDocument: types.BaseDocument{
					ID: message.ID,
				},
				ID:             message.ID,
				DIDCommMessage: message,
				Folder:         types.MailioFolderInbox, // TODO!: based on the recipient's handshakes
				Created:        time.Now().UnixMilli(),
			}
		}
		mailioMessage.MTPStatusCodes = append(mailioMessage.MTPStatusCodes, types.NewMTPStatusCode(2, 0, 0, "successfully received message"))

		_, sErr := msq.userService.SaveMessage(recAddress, mailioMessage)
		if sErr != nil {
			global.Logger.Log(sErr.Error(), "failed to save message", recAddress)
			// send error message to sender
			deliveryStatuses = append(deliveryStatuses, types.NewMTPStatusCode(5, 4, 4, fmt.Sprintf("failed to save message for %s", recAddress), types.WithRecAddress(recAddress)))
		} else {
			deliveryStatuses = append(deliveryStatuses, types.NewMTPStatusCode(2, 0, 0, fmt.Sprintf("message received by %s", recAddress), types.WithRecAddress(recAddress)))
		}
	}
	//send delivery message to sender
	deliveryMsg := &types.PlainBodyDelivery{
		StatusCodes: deliveryStatuses,
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

// handles DIDComm delivery notification (e.g. delivery failed, message refused, etc.)
func (msq *MessageQueue) handleDIDCommDelivery(message *types.DIDCommMessage) error {
	/*
		1. Find the message with existing message ID in users database (that this message is intended for)
	*/
	toUsers := message.To
	if len(toUsers) == 0 {
		// no recipients found
		return fmt.Errorf("no recipients found: %w", asynq.SkipRetry)
	}
	// extract the delivery MTPCodes
	body, bErr := base64.StdEncoding.DecodeString(message.PlainBodyBase64)
	if bErr != nil {
		global.Logger.Log(bErr.Error(), "failed to decode delivery message")
		return fmt.Errorf("failed to decode delivery message: %v: %w", bErr, asynq.SkipRetry)
	}
	var plainBody types.PlainBodyDelivery
	pErr := json.Unmarshal(body, &plainBody)
	if pErr != nil {
		global.Logger.Log(pErr.Error(), "failed to unmarshal delivery message")
		return fmt.Errorf("failed to unmarshal delivery message: %v: %w", pErr, asynq.SkipRetry)
	}
	for _, to := range message.To {
		parsedDid, pErr := did.ParseDID(to)
		if pErr != nil {
			global.Logger.Log(pErr.Error(), "failed to parse recipient DID", to)
			continue
		}
		address := parsedDid.Fragment()
		// find previously sent message ID
		mailioMessage, err := msq.userService.GetMessage(address, message.ID)
		if err != nil {
			global.Logger.Log(err.Error(), "failed to get message", address)
			continue
		}
		mailioMessage.MTPStatusCodes = append(mailioMessage.MTPStatusCodes, plainBody.StatusCodes...)
		_, sErr := msq.userService.SaveMessage(address, mailioMessage)
		if sErr != nil {
			global.Logger.Log(sErr.Error(), "failed to save message", address)
			return fmt.Errorf("failed to save message: %v: %w", sErr, asynq.SkipRetry)
		}
	}
	return nil
}
