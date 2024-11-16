package queue

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/hibiken/asynq"
	"github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

func (msq *MessageQueue) selectMailFolder(fromDID did.DID, recipientAddress string) (string, error) {
	// 1. if message to self, then it goes to inbox
	if fromDID.Fragment() == recipientAddress {
		return types.MailioFolderInbox, nil
	}
	// 2. Check if handhsake is accepted (then go to inbox)
	// GET handshake by fromDID address
	handshake, hErr := msq.handshakeService.GetByMailioAddress(recipientAddress, fromDID.Fragment())
	if hErr != nil && hErr != types.ErrNotFound {
		global.Logger.Log(hErr.Error(), "failed to get handshake", recipientAddress, fromDID.Fragment())
		return types.MailioFolderInbox, hErr
	}
	if handshake != nil && handshake.Content.Status == types.HANDSHAKE_STATUS_ACCEPTED {
		return types.MailioFolderInbox, nil
	} else if handshake != nil && handshake.Content.Status == types.HANDSHAKE_STATUS_REVOKED {
		return types.MailioFolderSpam, types.ErrHandshakeRevoked
	}

	// 3. Check the number of sent messages in the past 3 months to the same recipient
	now := time.Now().UTC()
	monthsAgo := now.AddDate(0, -3, 0)

	// check the number of sent messages in the past 3 months (read = true is by default for sent messages)
	totalMessagesSent, err := msq.userService.CountNumberOfMessages(recipientAddress, recipientAddress, types.MailioFolderSent, true, monthsAgo.UnixMilli(), now.UnixMilli())
	if err != nil {
		global.Logger.Log(err.Error(), "failed to count number of read messages", recipientAddress, fromDID.Fragment())
		return types.MailioFolderInbox, err
	}

	sentTotal := util.SumUpItemsFromFolderCountResponse([]string{types.MailioFolderSent}, totalMessagesSent)

	// if sent more than 1 email to this recipient in the past 3 months, then the message goes to inbox
	if sentTotal > 0 {
		return types.MailioFolderInbox, nil
	}

	// 4. check the read vs received ratio
	fromTimestamp := int64(0)
	toTimestamp := time.Now().UnixMilli()
	totalMessagesReceived, err := msq.userService.CountNumberOfMessages(recipientAddress, fromDID.Fragment(), "", false, fromTimestamp, toTimestamp)
	if err != nil {
		global.Logger.Log(err.Error(), "failed to count number of received messages", recipientAddress, fromDID.Fragment())
		return types.MailioFolderInbox, err
	}
	totalMessagesRead, err := msq.userService.CountNumberOfMessages(recipientAddress, fromDID.Fragment(), "", true, fromTimestamp, toTimestamp)
	if err != nil {
		global.Logger.Log(err.Error(), "failed to count number of read messages", recipientAddress, fromDID.Fragment())
		return types.MailioFolderInbox, err
	}

	// if the recipient has read more than X% of the messages, then the message goes to inbox
	total := util.SumUpItemsFromFolderCountResponse([]string{types.MailioFolderInbox, types.MailioFolderArchive, types.MailioFolderGoodReads, types.MailioFolderOther, types.MailioFolderTrash}, totalMessagesReceived)
	if total == 0 {
		return types.MailioFolderOther, nil
	}

	// find domain specific setttings
	readVsReceivedPercent := global.Conf.Mailio.ReadVsReceived

	// read := collectFoldersExceptSent(totalMessagesRead)
	read := util.SumUpItemsFromFolderCountResponse([]string{types.MailioFolderInbox, types.MailioFolderArchive, types.MailioFolderGoodReads, types.MailioFolderOther, types.MailioFolderTrash}, totalMessagesRead)
	readPercent := math.Ceil(float64(float32(read) / float32(total) * 100))
	if readPercent >= float64(readVsReceivedPercent) {
		return types.MailioFolderInbox, nil
	}
	return types.MailioFolderOther, nil
}

// handleReceivedDIDCommMessage handles received DIDComm messages
// 1. Extracts the sender's DID and gets the service endpoint where the message was sent from
// 2. Collects local recipients of the message
// 3. Collects delivery status codes
// 4. Sends delivery message to the sender
func (msq *MessageQueue) handleReceivedDIDCommMessage(message *types.DIDCommMessage) error {

	// get the senders DID and get the service endpoint where message was sent from
	fromDID, fdErr := did.ParseDID(message.From)
	if fdErr != nil {
		//the sender cannot be validated, no retryies are allowed. Message fails permanently
		global.Logger.Log(fdErr.Error(), "failed to parse sender DID", message.From)
		return fmt.Errorf("failed to parse sender DID: %v: %w", fdErr, asynq.SkipRetry)
	}

	// get and cache the senders DID document
	_, cErr := msq.ssiService.FetchDIDByWebDID(fromDID)
	if cErr != nil {
		global.Logger.Log(cErr.Error(), "failed to cache sender DID document", message.From)
		// continue processing the message regardless of the error. Client can get the missing did document later
	}

	domain := fromDID.Value()
	serverDID, didErr := msq.mtpService.GetServerDIDDocument(domain)
	if didErr != nil {
		global.Logger.Log(didErr.Error(), "failed retrieving Mailio DID document", domain)
		return fmt.Errorf("failed retrieving Mailio DID document: %v: %w", didErr, asynq.SkipRetry)
	}
	endpoint := util.ExtractDIDMessageEndpoint(serverDID)
	if endpoint == "" {
		// Bad destination address syntax
		return fmt.Errorf("unable to route message to %s for %s: %w", endpoint, serverDID.ID.String(), asynq.SkipRetry)
	}

	// collect local recipients of the message
	localRecipientsAddresses := []string{}
	addedMap := map[string]string{} // keeping track of added recipients
	hasExcludedSelf := false
	for _, recipient := range message.EncryptedBody.Recipients {
		// skip sender address if exists in the message itself
		// but only once (since it might be sending to one self)
		if recipient.Header.Kid == message.From && !hasExcludedSelf {
			hasExcludedSelf = true
			continue
		}
		recAddress := recipient.Header.Kid

		parsedDid, pErr := did.ParseDID(recAddress)
		if pErr != nil {
			// skip if parsing fails
			global.Logger.Log(pErr.Error(), "failed to parse recipient DID", recAddress)
			continue
		}

		// collects only recipients that might be on this server based on the DIDs
		// since message may contain messages to recipients on multiple different servers
		if parsedDid.Value() == global.Conf.Mailio.ServerDomain {
			if _, ok := addedMap[parsedDid.Fragment()]; !ok { // if not yet added
				localRecipientsAddresses = append(localRecipientsAddresses, parsedDid.Fragment())
				addedMap[parsedDid.Fragment()] = parsedDid.Fragment()
			}
		}
	}

	// collect delivery status codes (possible than more than 1)
	deliveryStatuses := []*types.MTPStatusCode{}
	if len(localRecipientsAddresses) == 0 {
		// Handles the case when there are no local recipients.
		deliveryStatuses = append(deliveryStatuses, types.NewMTPStatusCode(5, 4, 4, "no local recipients found"))
	}

	for _, recAddress := range localRecipientsAddresses {
		// select folder based on the recipient's handshakes and statistics
		folder, fErr := msq.selectMailFolder(fromDID, recAddress)
		if fErr != nil {
			if fErr == types.ErrHandshakeRevoked {
				deliveryStatuses = append(deliveryStatuses, types.NewMTPStatusCode(5, 8, 2, fmt.Sprintf("handshake revoked for %s", recAddress), types.WithRecAddress(recAddress)))
				continue
			}
		}
		// in case request is a handshake request
		if message.Intent == types.DIDCommIntentHandshake {
			folder = types.MailioFolderHandshake
		}

		isReplied := false
		if message.Pthid != "" {
			isReplied = true
		}

		// handle attachment by decupting the links and downloading the content
		if len(message.Attachments) > 0 {
			for _, att := range message.Attachments {
				content, dErr := base64.StdEncoding.DecodeString(att.Data.Base64)
				if dErr != nil {
					global.Logger.Log(dErr.Error(), "failed to decode attachment")
					// TODO: store message_delivery error?
				}
				// calc the hash
				md5Hash := md5.New()
				md5Hash.Write(content)
				att.Data.Hash = fmt.Sprintf("%x", md5Hash.Sum(nil))

				now := time.Now().UTC().Format("20061010t150405")
				path := recAddress + "/" + att.Data.Hash + "_" + now

				link, uErr := msq.s3Service.UploadAttachment(global.Conf.Storage.Bucket, path, content)
				if uErr != nil {
					global.Logger.Log(uErr.Error(), "failed to upload attachment")
					//TODO: store message_delivery error?
				}
				fmt.Printf("Attachment uploaded to %s\n", link)
				if att.Data.Links == nil {
					att.Data.Links = []string{}
				}
				att.Data.Links = append(att.Data.Links, link) // link attachment to the storage
				att.Data.Base64 = ""                          // remove the attachment from the message itself
			}
		}

		uniqueID, _ := util.DIDDocumentToUniqueID(message, folder)
		mailioMessage := &types.MailioMessage{
			ID:             uniqueID,
			DIDCommMessage: message,
			Folder:         folder,
			IsRead:         false,
			IsReplied:      isReplied,
			From:           message.From,
			Created:        time.Now().UnixMilli(),
		}

		fmt.Printf("Saving message for user %s, mailio id: %s, didcommid: %s\n", recAddress, mailioMessage.ID, mailioMessage.DIDCommMessage.ID)
		_, sErr := msq.userService.SaveMessage(recAddress, mailioMessage)
		if sErr != nil {
			global.Logger.Log(sErr.Error(), "(receive message) failed to save message", recAddress)
			// send error message to sender
			deliveryStatuses = append(deliveryStatuses, types.NewMTPStatusCode(5, 4, 4, fmt.Sprintf("failed to save message for %s", recAddress), types.WithRecAddress(recAddress)))
		} else {
			deliveryStatuses = append(deliveryStatuses, types.NewMTPStatusCode(2, 0, 0, "delivery confirmation", types.WithRecAddress(recAddress)))
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
	thisServerDIDDoc, err := util.CreateMailioDIDDocument()
	if err != nil {
		global.Logger.Log(err.Error(), "failed to create Mailio DID document")
		return fmt.Errorf("failed to create Mailio DID document: %v: %w", err, asynq.SkipRetry)
	}
	didMessage := &types.DIDCommMessage{
		ID:              message.ID,
		Intent:          types.DIDCommIntentDelivery,
		Type:            "application/didcomm-signed+json",
		From:            "did:web:" + global.Conf.Mailio.ServerDomain + ":" + thisServerDIDDoc.ID.Value(), // this server DID
		To:              []string{message.From},
		PlainBodyBase64: base64.StdEncoding.EncodeToString(deliveryMsgStr),
	}
	sndCode, sndErr := msq.httpSend(didMessage, endpoint)
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
	if len(plainBody.StatusCodes) > 0 {
		msq.deliveryService.SaveBulkMtpStatusCodes(message.ID, plainBody.StatusCodes)
	}

	return nil
}
