package queue

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/hibiken/asynq"
	"github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

/**
* selectMailFolder selects the mail folder primarly based on existence and status of a handshake
* and secondary based on the sender and recipient statistics if handshake does not exist.
 */
func (msq *MessageQueue) selectMailFolder(fromAddress string, recipientAddress string) (string, error) {
	// 1. if message to self, then it goes to inbox
	if fromAddress == recipientAddress {
		return types.MailioFolderInbox, nil
	}
	// 2. Check if handhsake is accepted (then go to inbox)
	// GET handshake by fromDID address
	handshake, hErr := services.GetHandshakeByMailioAddress(msq.userRepo, recipientAddress, fromAddress)
	if hErr != nil && hErr != types.ErrNotFound {
		global.Logger.Log(hErr.Error(), "failed to get handshake", recipientAddress, fromAddress)
		// do nothing, continue to statistics
	}
	if handshake != nil && handshake.Content.Status == types.HANDSHAKE_STATUS_ACCEPTED {
		return types.MailioFolderInbox, nil
	} else if handshake != nil && handshake.Content.Status == types.HANDSHAKE_STATUS_REVOKED {
		return types.MailioFolderSpam, nil
	} else if handshake != nil && handshake.Content.Status == types.HANDSHAKE_STATUS_REQUEST {
		return types.MailioFolderHandshake, nil
	}

	// 3. Check the number of sent messages in the past to the same recipient
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	totalMessagesSent, err := msq.statisticsService.GetEmailStatistics(ctx, fromAddress, recipientAddress)
	if err != nil {
		global.Logger.Log(err.Error(), "failed to count number of read messages", recipientAddress, fromAddress)
		return types.MailioFolderInbox, err
	}

	// if sent more than 1 email to this recipient in the past 3 months, then the message goes to inbox
	if totalMessagesSent > 0 {
		return types.MailioFolderInbox, nil
	}

	// 4. check the read vs received ratio
	totalMessagesReceived, err := msq.statisticsService.GetEmailStatistics(ctx, fromAddress, recipientAddress)
	if err != nil {
		global.Logger.Log(err.Error(), "failed to count number of received messages", recipientAddress, fromAddress)
		return types.MailioFolderInbox, err
	}
	totalInterest, err := msq.statisticsService.GetEmailInterest(ctx, fromAddress, recipientAddress)
	if err != nil {
		global.Logger.Log(err.Error(), "failed to count number of read messages", recipientAddress, fromAddress)
		return types.MailioFolderInbox, err
	}

	// if new sender, then the message goes to inbox
	if totalMessagesReceived == 0 {
		return types.MailioFolderInbox, nil
	}

	// find domain specific setttings
	interestVsReceivedPercent := global.Conf.Mailio.ReadVsReceived

	// if the recipient has show interest in more than X% of the messages, then the message goes to good reads
	interestPercent := math.Ceil(float64(float32(totalInterest) / float32(totalMessagesReceived) * 100))
	if interestPercent >= float64(interestVsReceivedPercent) {
		return types.MailioFolderGoodReads, nil
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
		// in case request is a handshake request
		var folder string
		if message.Intent == types.DIDCommIntentHandshake || message.Intent == types.DIDCommIntentHandshakeRequest || message.Intent == types.DIDCommIntentHandshakeResponse {
			folder = types.MailioFolderHandshake
			// also check the nonce and if it is a valid handshake request
			if !msq.isNonceValid(message.PlainBodyBase64) {
				// invalid nonce (drop the message)
				global.Logger.Log("invalid nonce", "failed to validate nonce", recAddress, "msg id: ", message.ID, "from: ", message.From)
				continue
			}
		} else {
			// select folder based on the recipient's handshakes and statistics
			f, fErr := msq.selectMailFolder(fromDID.String(), recAddress)
			if fErr != nil {
				if fErr == types.ErrHandshakeRevoked {
					deliveryStatuses = append(deliveryStatuses, types.NewMTPStatusCode(5, 8, 2, fmt.Sprintf("handshake revoked for %s", recAddress), types.WithRecAddress(recAddress)))
					continue
				}
			}
			folder = f
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

				link, uErr := msq.s3Service.UploadAttachment(global.Conf.Storage.Bucket, path, content, "")
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

		mailioMessage := &types.MailioMessage{
			ID:             message.ID,
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

	// iterate over all local recipients and store statistics
	for _, recAddress := range localRecipientsAddresses {
		fullWebDID := "did:web:" + global.Conf.Mailio.ServerDomain + "#" + recAddress
		msq.statisticsService.ProcessEmailStatistics(fromDID.String(), fullWebDID)
	}

	// reply with delivery message to sender of this message
	if len(deliveryStatuses) > 0 {
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

/*
*
Sends an encrypted DIDComm message to the specified recipient(s).
The message is validated, logged, and optionally saved in a local database.
It handles attachments, validates recipient addresses, and routes the message to the appropriate endpoints.
*
*/
func (msq *MessageQueue) DIDCommSendMessage(userAddress string, input *types.DIDCommMessageInput) error {
	message := input.DIDCommMessage
	global.Logger.Log("sending from", userAddress, "intent", message.Intent)

	if message.Thid == "" {
		message.Thid = message.ID // if there is no thid, use message id
	}

	// struct to store in local database
	mailioMessage := types.MailioMessage{
		ID:             message.ID,
		From:           message.From,
		DIDCommMessage: &message,
		Created:        time.Now().UnixMilli(),
		Folder:         types.MailioFolderSent,
		IsRead:         true, // sent messages are by default read
	}

	//validate recipients (checks if they are valid DIDs and if they are reachable via HTTP/HTTPS)
	// alternatively validateRecipientDIDFromEmails can be used to validate recipients from emails
	recipientDidMap := map[string]did.Document{}
	mtpStatusErrors := []*types.MTPStatusCode{}
	if len(message.To) > 0 {
		recMap, mtpErrors := msq.validateRecipientDIDs(&message)
		recipientDidMap = recMap
		mtpStatusErrors = mtpErrors
	} else if len(message.ToEmails) > 0 {
		recMap, mtpErrors := msq.validateRecipientDIDFromEmails(&message)
		for k, v := range recMap {
			recipientDidMap[k] = v
		}
		mtpStatusErrors = append(mtpStatusErrors, mtpErrors...)
	} else {
		// no recipients
		mtpStatusErrors = append(mtpStatusErrors, types.NewMTPStatusCode(5, 1, 1, "no recipients"))
	}

	// collect endpoints
	endpointMap := make(map[string]string)

	// iterating over recipient map and sending messages
	for _, didDoc := range recipientDidMap {
		// didDoc ID has format e.g. did:mailio:0xabc, while from has web format (e.g. did:web:mail.io#0xabc)
		// find a service endpoint for a recipient from DID Document
		endpoint := util.ExtractDIDMessageEndpoint(&didDoc)
		if endpoint == "" {
			// Bad destination address syntax
			mtpStatusErrors = append(mtpStatusErrors, types.NewMTPStatusCode(5, 1, 3, fmt.Sprintf("unable to route message to %s for %s", endpoint, didDoc.ID.String())))
			continue
		}
		endpointMap[endpoint] = endpoint
	}

	// download attachment data from s3
	// a deep copy of the sending object (message) is made to avoid modifying the original object
	// this is due to the attachments are being attached to the original message instad reference to the local storage
	var messageDeepCopy types.DIDCommMessage
	cpErr := util.DeepCopy(&message, &messageDeepCopy)
	if cpErr != nil {
		global.Logger.Log(cpErr.Error(), "failed to copy message")
		return fmt.Errorf("failed to copy message: %v: %w", cpErr, asynq.SkipRetry)
	}
	for _, att := range messageDeepCopy.Attachments {
		if len(att.Data.Links) > 0 {
			for _, link := range att.Data.Links {
				if strings.Contains(link, "?enc=1") {
					url := strings.Replace(link, "?enc=1", "", 1)
					content, dErr := msq.s3Service.DownloadAttachment(url)
					if dErr != nil {
						global.Logger.Log(dErr.Error(), "failed to download attachment")
						// TODO: store message_delivery error?
						return fmt.Errorf("failed downloading attachment: %v: %w", dErr, asynq.SkipRetry)
					}
					att.Data.Base64 = base64.StdEncoding.EncodeToString(content)
				}
			}
			att.Data.Links = nil
		}
	}

	// send message to each endpoint extracted from DID documents
	for _, ep := range endpointMap {
		code, sendErr := msq.httpSend(&messageDeepCopy, ep)
		if sendErr != nil {
			if sendErr == types.ErrContinue {
				// on to the next message if this one failed
				mtpStatusErrors = append(mtpStatusErrors, code)
				continue
			}
			return sendErr
		}
	}
	// if no errors, append success message
	if len(mtpStatusErrors) == 0 {
		mtpStatusErrors = append(mtpStatusErrors, types.NewMTPStatusCode(2, 0, 0, "message sent"))
	}
	// store mailioMessage in database (sent folder of the sender), unless handshake request
	if message.Intent != types.DIDCommIntentHandshakeRequest && message.Intent != types.DIDCommIntentHandshakeResponse {
		_, sErr := msq.userService.SaveMessage(userAddress, &mailioMessage)
		if sErr != nil {
			global.Logger.Log(sErr.Error(), "(sendMessage) failed to save message", userAddress)
			return sErr
		}
		msq.deliveryService.SaveBulkMtpStatusCodes(message.ID, mtpStatusErrors)
	}

	// statistics (including handshake requests)
	sender := "did:web:" + global.Conf.Mailio.ServerDomain + "#" + userAddress
	msq.statisticsService.ProcessEmailsSentStatistics(sender)
	// store all recipients in statistics
	for _, didDoc := range recipientDidMap {
		msq.statisticsService.ProcessEmailStatistics(sender, didDoc.ID.String())
	}

	// delete attachments that client wants to delete
	// remove possible attachments to be removed
	// (the client reports those when only 1 type of recipient is present, but both encrypted and plain attachments are uploaded)
	for _, att := range input.DeleteAttachments {
		// delete attachment
		link, lpErr := url.Parse(att)
		if lpErr != nil {
			global.Logger.Log(lpErr.Error(), "failed to parse attachment link", att)
			continue
		}
		// extract bucket and path (the path is not completely trusted. So only in userSender folder can it be deleted)
		parts := strings.Split(link.Path, "/")
		fileKey := userAddress + "/" + parts[len(parts)-1]
		if fileKey == "" {
			global.Logger.Log("error", "invalid attachment url", "attachmentUrl", att)
			return fmt.Errorf("invalid attachment url: %v: %w", lpErr, asynq.SkipRetry)
		}
		dErr := msq.s3Service.DeleteAttachment(global.Conf.Storage.Bucket, fileKey)
		if dErr != nil {
			global.Logger.Log(dErr.Error(), "failed to delete attachment", att)
		}
	}
	return nil
}
