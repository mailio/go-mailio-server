package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"github.com/hibiken/asynq"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

const taskDelaySeconds = 5

type MessagingApi struct {
	ssiService         *services.SelfSovereignService
	validate           *validator.Validate
	env                *types.Environment
	userService        *services.UserService
	userProfileService *services.UserProfileService
	domainService      *services.DomainService
	statisticsService  *services.StatisticsService
}

func NewMessagingApi(ssiService *services.SelfSovereignService,
	userService *services.UserService,
	userProfileService *services.UserProfileService,
	domainService *services.DomainService,
	statsService *services.StatisticsService,
	env *types.Environment) *MessagingApi {

	validate := validator.New()

	return &MessagingApi{
		validate:           validate,
		ssiService:         ssiService,
		env:                env,
		userService:        userService,
		userProfileService: userProfileService,
		domainService:      domainService,
		statisticsService:  statsService,
	}
}

// Send end-to-end encrypted message to a DID recipients
// @Summary Send end-to-end encrypted message to DID recipients
// @Security Bearer
// @Description Send end-to-end encrypted message to DID recipients
// @Tags Messaging
// @Accept json
// @Produce json
// @Param message body types.DIDCommMessage true "didcomm-encrypted+json"
// @Success 202 {object} types.DIDCommApiResponse
// @Failure 400 {object} api.ApiError "bad request"
// @Failure 401 {object} api.ApiError "invalid signature or unauthorized to send messages"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/senddid [post]
func (ma *MessagingApi) SendDIDMessage(c *gin.Context) {
	address, exists := c.Get("subjectAddress")
	if !exists {
		ApiErrorf(c, http.StatusInternalServerError, "jwt invalid")
		return
	}

	// input DIDCommMessage
	var input types.DIDCommMessageInput
	if err := c.ShouldBindBodyWith(&input, binding.JSON); err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid format")
		return
	}

	// validate input
	err := ma.validate.Struct(input)
	if err != nil {
		msg := util.ValidationErrorToMessage(err)
		ApiErrorf(c, http.StatusBadRequest, "%s", msg)
		return
	}
	// get user profile
	userProfile, exists := c.Get("userProfile")
	if !exists {
		ApiErrorf(c, http.StatusForbidden, "JWT invalid")
		return
	}
	up := userProfile.(*types.UserProfile)

	if !up.Enabled {
		ApiErrorf(c, http.StatusForbidden, "User disabled")
		return
	}

	totalDiskUsageFromHandlers := util.GetDiskUsageFromDiskHandlers(address.(string))
	stats, sErr := ma.userProfileService.Stats(address.(string))
	if sErr != nil {
		global.Logger.Log("error retrieving disk usage stats", sErr.Error())
	}
	activeSize := int64(0)
	if stats != nil {
		activeSize = stats.ActiveSize
	}
	if totalDiskUsageFromHandlers+activeSize >= up.DiskSpace {
		ApiErrorf(c, http.StatusRequestEntityTooLarge, "Disk space exceeded")
		return
	}

	id, sndErr := ma.sendDIDCommMessage(address.(string), input)
	if sndErr != nil {
		ma.handleSendMessageApiError(c, sndErr)
		return
	}

	c.JSON(http.StatusAccepted, types.DIDCommApiResponse{DIDCommID: *id})
}

// Send SMTP email
// @Summary Send SMTP email
// @Security Bearer
// @Description Send SMTP email
// @Tags Messaging
// @Accept json
// @Produce json
// @Param email body mailiosmtp.Mail true "smtp email"
// @Success 202 {object} mailiosmtp.Mail
// @Failure 400 {object} api.ApiError "bad request"
// @Failure 401 {object} api.ApiError "invalid signature or unauthorized to send messages"
// @Failure 403 {object} api.ApiError "user not authorized"
// @Failure 413 {object} api.ApiError "message too large"
// @Failure 422 {object} api.ApiError "no recipient/no subject body/too many attachments"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/sendsmtp [post]
func (ma *MessagingApi) SendSmtpMessage(c *gin.Context) {

	address, exists := c.Get("subjectAddress")
	if !exists {
		ApiErrorf(c, http.StatusForbidden, "Unauthorized")
		return
	}

	var mail types.SmtpEmailInput
	if err := c.ShouldBindJSON(&mail); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// get user profile
	userProfile, exists := c.Get("userProfile")
	if !exists {
		ApiErrorf(c, http.StatusForbidden, "JWT invalid")
		return
	}
	up := userProfile.(*types.UserProfile)

	if !up.Enabled {
		ApiErrorf(c, http.StatusForbidden, "User disabled")
		return
	}

	totalDiskUsageFromHandlers := util.GetDiskUsageFromDiskHandlers(address.(string))
	stats, sErr := ma.userProfileService.Stats(address.(string))
	if sErr != nil {
		global.Logger.Log("error retrieving disk usage stats", sErr.Error())
	}
	activeSize := int64(0)
	if stats != nil {
		activeSize = stats.ActiveSize
	}
	if totalDiskUsageFromHandlers+activeSize >= up.DiskSpace {
		ApiErrorf(c, http.StatusRequestEntityTooLarge, "Disk space exceeded")
		return
	}

	id, err := ma.sendSMTPMessage(c, &mail, up)
	if err != nil {
		ma.handleSendMessageApiError(c, err)
	}

	c.JSON(http.StatusAccepted, types.DIDCommApiResponse{SmtpID: *id})
}

// Cancel send (SMTP or DIDComm)
// @Summary Cancel send (SMTP or DIDComm)
// @Security Bearer
// @Description Cancel send (SMTP or DIDComm)
// @Tags Messaging
// @Accept json
// @Produce json
// @Param email body types.DIDCommApiResponse true "task ids to cancel"
// @Success 202 {object} types.DIDCommApiResponse
// @Failure 400 {object} api.ApiError "bad request"
// @Failure 401 {object} api.ApiError "invalid signature or unauthorized to cancel messages"
// @Failure 403 {object} api.ApiError "user not authorized"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/sendcancel [post]
func (ma *MessagingApi) CancelSend(c *gin.Context) {
	// get the task id
	var msgIds types.DIDCommApiResponse
	if err := c.ShouldBindJSON(&msgIds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if msgIds.DIDCommID != "" {
		// cancel DIDComm message
		_, tsErr := ma.env.RedisClient.Set(ctx, fmt.Sprintf("cancel:%s", msgIds.DIDCommID), msgIds.DIDCommID, time.Second*30).Result()
		if tsErr != nil {
			ApiErrorf(c, http.StatusInternalServerError, "failed to cancel task")
			return
		}
	}
	if msgIds.SmtpID != "" {
		_, tsErr := ma.env.RedisClient.Set(ctx, fmt.Sprintf("cancel:%s", msgIds.SmtpID), msgIds.SmtpID, time.Second*30).Result()
		if tsErr != nil {
			ApiErrorf(c, http.StatusInternalServerError, "failed to cancel task")
			return
		}
	}
	c.JSON(http.StatusAccepted, &msgIds)
}

// check if user is honest about the from email address
// if not, return unauthorized
func (ma *MessagingApi) validateSmtpSender(c *gin.Context, fromEmailAddress string) error {
	scryptedMail, err := util.ScryptEmail(fromEmailAddress)
	if err != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to scrypt email address")
		return err
	}
	_, mErr := ma.userService.FindUserByScryptEmail(scryptedMail)
	if mErr != nil {
		if mErr == types.ErrNotFound {
			ApiErrorf(c, http.StatusForbidden, "From email address and your address don't match")
			return err
		}
		global.Logger.Log(mErr.Error(), "failed to find user by scryped email")
		ApiErrorf(c, http.StatusInternalServerError, "failed to find user by scryped email")
		return err
	}

	// all ok
	return nil
}

// sendSMTPMessage sends an email message via SMTP protocol
// func (ma *MessagingApi) sendSMTPMessage(c *gin.Context, mail *smtptypes.Mail, up *types.UserProfile) (*string, error) {
func (ma *MessagingApi) sendSMTPMessage(c *gin.Context, mailInput *types.SmtpEmailInput, up *types.UserProfile) (*string, error) {
	// send email
	// check daily sent limit (default = 10)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	day := time.Now().UTC().Truncate(24 * time.Hour).Unix()
	countSent, csErr := ma.statisticsService.GetEmailSentByDay(ctx, up.ID, day)
	if csErr != nil {
		global.Logger.Log("error counting number of sent messages to email", csErr.Error())
	}
	if countSent > int64(global.Conf.Mailio.DailySmtpSentLimit) {
		return nil, types.ErrTooManyRequests
	}

	// validate if sender can send emails
	//TODO: Add a check if domain is a valid domain to be sent from
	vsErr := ma.validateSmtpSender(c, mailInput.From)
	if vsErr != nil {
		return nil, types.ErrNotAuthorized
	}
	// validate input
	if len(mailInput.To) == 0 {
		return nil, types.ErrNoRecipient
	}
	// asses email size (max 3MB)
	sizeBytes := 0
	if mailInput.BodyHTML != nil {
		sizeBytes += len(*mailInput.BodyHTML)
	}
	if mailInput.BodyText != nil {
		sizeBytes += len(*mailInput.BodyText)
	}
	if sizeBytes > 7*1024*1024 { // maximum total allowed size
		ApiErrorf(c, http.StatusBadRequest, "message too large")
		return nil, types.ErrMessageTooLarge
	}
	if len(mailInput.Attachments) > 50 { // maximum allowed attachments
		ApiErrorf(c, http.StatusBadRequest, "too many attachments")
		return nil, types.ErrTooManyAttachments
	}
	if len(mailInput.To) > 50 { // maximum allowed recipients
		return nil, types.ErrTooManyRecipients
	}
	if util.IsNilOrEmpty(mailInput.Subject) && util.IsNilOrEmpty(mailInput.BodyHTML) && util.IsNilOrEmpty(mailInput.BodyText) {
		// ApiErrorf(c, http.StatusBadRequest, "no subject or body")
		return nil, types.ErrBadRequestMissingSubjectOrBody
	}
	// add to queue
	task := &types.SmtpTask{
		Mail:    mailInput,
		Address: up.ID,
	}
	sendTask, tErr := types.NewSmtpCommSendTask(task)
	if tErr != nil {
		return nil, tErr
	}

	id, idErr := util.SmtpMailToUniqueID(mailInput, types.MailioFolderSent)
	if idErr != nil {
		return nil, idErr
	}

	taskInfo, tqErr := ma.env.TaskClient.Enqueue(sendTask,
		asynq.MaxRetry(3),             // max number of times to retry the task
		asynq.Timeout(60*time.Second), // max time to process the task
		asynq.TaskID(id),              // unique task id
		asynq.ProcessIn(time.Second*time.Duration(taskDelaySeconds)), // delay processing for 5 seconds (user has time to cancel the smtp send)
		asynq.Unique(time.Second*10))                                 // unique for 10 seconds (preventing multiple equal messages in the queue)
	if tqErr != nil {
		global.Logger.Log(tqErr.Error(), "failed to send message")
		return nil, tqErr
	}
	global.Logger.Log(fmt.Sprintf("message SMTP sent: %s", taskInfo.ID), "message queued")
	return &id, nil
}

// sendDIDCommMessage sends a DIDComm message
func (ma *MessagingApi) sendDIDCommMessage(senderAddress string, input types.DIDCommMessageInput) (*string, error) {
	// validate input
	if len(input.DIDCommMessage.To) == 0 && len(input.DIDCommMessage.ToEmails) == 0 {
		return nil, types.ErrNoRecipient
	}
	if len(input.DIDCommMessage.ToEmails) > 50 { // maximum allowed recipients
		return nil, types.ErrTooManyRecipients
	}
	if len(input.DIDCommMessage.EncryptedBody.Ciphertext) > 3*1024*1024 { // maximum total allowed size
		return nil, types.ErrMessageTooLarge
	}
	if len(input.DIDCommMessage.Attachments) > 50 { // maximum allowed attachments
		return nil, types.ErrTooManyAttachments
	}

	// default is messaging
	if input.DIDCommMessage.Intent == "" {
		input.DIDCommMessage.Intent = types.DIDCommIntentMessage
	}

	// get the user profile
	userProfile, upErr := ma.userProfileService.Get(senderAddress)
	if upErr != nil {
		global.Logger.Log(upErr.Error(), "failed to get user profile")
		return nil, types.ErrInternal
	}
	if !userProfile.Enabled {
		return nil, types.ErrNotAuthorized
	}

	// get the senders domain (which should in the database already, so no resolving needed)
	senderDidDoc, sndDidErr := ma.ssiService.GetDIDDocument(senderAddress)
	if sndDidErr != nil {
		global.Logger.Log(sndDidErr.Error(), "failed to get sender DID document")
		return nil, types.ErrInternal
	}
	senderDomain := util.ExtractDIDMessageEndpoint(senderDidDoc)
	if senderDomain == "" {
		global.Logger.Log("sender domain is empty", "failed to get sender domain")
		return nil, types.ErrInternal
	}
	parsedSenderUrl, pUrlErr := url.Parse(senderDomain)
	if pUrlErr != nil {
		global.Logger.Log(pUrlErr.Error(), "failed to parse sender domain")
		return nil, types.ErrInternal
	}
	// host, port, _ := net.SplitHostPort(parsedSenderUrl.Host)

	// enforce the from address to be a web DID
	input.DIDCommMessage.From = fmt.Sprintf("did:web:%s#%s", parsedSenderUrl.Host, senderAddress)

	// intended folder for sender is "sent"
	id, idErr := util.DIDDocumentToUniqueID(&input.DIDCommMessage, types.MailioFolderSent)
	if idErr != nil {
		global.Logger.Log(idErr.Error(), "failed to create unique id")
		return nil, types.ErrInternal
	}
	input.DIDCommMessage.ID = id
	input.DIDCommMessage.CreatedTime = time.Now().UTC().UnixMilli()

	task := &types.Task{
		Address:             senderAddress,
		DIDCommMessageInput: &input,
	}
	sendTask, tErr := types.NewDIDCommSendTask(task)
	if tErr != nil {
		global.Logger.Log(tErr.Error(), "failed to create task")
		return nil, types.ErrInternal
	}

	taskInfo, tqErr := ma.env.TaskClient.Enqueue(sendTask,
		asynq.MaxRetry(3),                     // max number of times to retry the task
		asynq.Timeout(60*time.Second),         // max time to process the task
		asynq.TaskID(input.DIDCommMessage.ID), // unique task id
		asynq.Unique(time.Second*10))          // unique for 10 seconds (preventing multiple equal messages in the queue)
	if tqErr != nil {
		global.Logger.Log(tqErr.Error(), "failed to send message")
		return nil, types.ErrInternal
	}
	global.Logger.Log(fmt.Sprintf("message sent: %s", taskInfo.ID), "message queued")

	return &id, nil
}

// sending API error handling
func (ma *MessagingApi) handleSendMessageApiError(c *gin.Context, err error) {
	if err == nil {
		return
	}
	switch err {
	case types.ErrNoRecipient:
		ApiErrorf(c, http.StatusUnprocessableEntity, "No recipient")
	case types.ErrNotAuthorized:
		ApiErrorf(c, http.StatusForbidden, "Not authorized to send from this email address")
	case types.ErrMessageTooLarge:
		ApiErrorf(c, http.StatusRequestEntityTooLarge, "Message too large")
	case types.ErrTooManyAttachments:
		ApiErrorf(c, http.StatusUnprocessableEntity, "Too many attachments")
	case types.ErrTooManyRecipients:
		ApiErrorf(c, http.StatusUnprocessableEntity, "Too many recipients")
	case types.ErrBadRequestMissingSubjectOrBody:
		ApiErrorf(c, http.StatusUnprocessableEntity, "Missing subject or body")
	default:
		ApiErrorf(c, http.StatusInternalServerError, "Failed to send message")
	}
	global.Logger.Log(err.Error(), "Failed to send message")
}
