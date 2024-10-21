package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"github.com/hibiken/asynq"
	smtptypes "github.com/mailio/go-mailio-server/email/smtp/types"
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
}

func NewMessagingApi(ssiService *services.SelfSovereignService, userService *services.UserService, userProfileService *services.UserProfileService, env *types.Environment) *MessagingApi {
	validate := validator.New()

	return &MessagingApi{
		validate:           validate,
		ssiService:         ssiService,
		env:                env,
		userService:        userService,
		userProfileService: userProfileService,
	}
}

// Send end-to-end encrypted message to a DID recipients
// @Summary Send end-to-end encrypted message to DID recipients
// @Security Bearer
// @Description Send end-to-end encrypted message to DID recipients
// @Tags Messaging
// @Accept json
// @Produce json
// @Param handshake body types.DIDCommMessage true "didcomm-encrypted+json"
// @Success 202 {object} types.DIDCommApiResponse
// @Failure 400 {object} api.ApiError "bad request"
// @Failure 401 {object} api.ApiError "invalid signature or unauthorized to send messages"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/senddid [post]
func (ma *MessagingApi) SendDIDMessage(c *gin.Context) {
	subjectAddress, exists := c.Get("subjectAddress")
	if !exists {
		ApiErrorf(c, http.StatusInternalServerError, "jwt invalid")
		return
	}

	// input DIDCommMessage
	var input types.DIDCommMessage
	if err := c.ShouldBindBodyWith(&input, binding.JSON); err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid format")
		return
	}

	// validate input
	err := ma.validate.Struct(input)
	if err != nil {
		msg := util.ValidationErrorToMessage(err)
		ApiErrorf(c, http.StatusBadRequest, msg)
		return
	}

	id, sndErr := ma.sendDIDCommMessage(subjectAddress.(string), input)
	if sndErr != nil {
		ma.handleSendMessageApiError(c, sndErr)
		return
	}

	c.JSON(http.StatusAccepted, types.DIDCommApiResponse{DIDCommID: *id})
}

//TODO: add API for canceling sending tasks

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
	var mail types.SmtpEmailInput
	if err := c.ShouldBindJSON(&mail); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// get user profile
	userProfile, exists := c.Get("userProfile")
	if !exists {
		ApiErrorf(c, http.StatusForbidden, "jwt invalid")
		return
	}
	up := userProfile.(*types.UserProfile)

	// convert to smtptypes.Mail
	mailEmail, meErr := convertToSmtpEmail(mail)
	if meErr != nil {
		if meErr == types.ErrInvalidFormat {
			ApiErrorf(c, http.StatusBadRequest, "Invalid sender email address")
		} else if meErr == types.ErrInvaidRecipient {
			ApiErrorf(c, http.StatusBadRequest, "Please check the recipient email addresses")
		}
		return
	}

	id, err := ma.sendSMTPMessage(c, mailEmail, up)
	if err != nil {
		ma.handleSendMessageApiError(c, err)
	}

	c.JSON(http.StatusAccepted, types.DIDCommApiResponse{SmtpID: *id})
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
func (ma *MessagingApi) sendSMTPMessage(c *gin.Context, mail *smtptypes.Mail, up *types.UserProfile) (*string, error) {
	// send email
	// check daily sent limit (default = 10)
	fromTimestamp := time.Now().UTC().AddDate(0, 0, -1).UnixMilli()
	toTimestamp := time.Now().UTC().UnixMilli()
	countSent, csErr := ma.userService.CountNumberOfSentMessages(up.ID, fromTimestamp, toTimestamp)
	if csErr != nil {
		global.Logger.Log("error counting number of sent messages to email", csErr.Error())
	}
	sent := util.SumUpItemsFromFolderCountResponse([]string{types.MailioFolderSent}, countSent)
	if sent > global.Conf.Mailio.DailySmtpSentLimit {
		return nil, types.ErrTooManyRequests
	}

	// validate if sender can send emails
	//TODO: Add a check if domain is a valid domain to be sent from
	vsErr := ma.validateSmtpSender(c, mail.From.Address)
	if vsErr != nil {
		return nil, types.ErrNotAuthorized
	}
	// validate input
	if len(mail.To) == 0 {
		return nil, types.ErrNoRecipient
	}
	if mail.SizeBytes > 3*1024*1024 { // maximum total allowed size
		ApiErrorf(c, http.StatusBadRequest, "message too large")
		return nil, types.ErrMessageTooLarge
	}
	if len(mail.Attachments) > 50 { // maximum allowed attachments
		ApiErrorf(c, http.StatusBadRequest, "too many attachments")
		return nil, types.ErrTooManyAttachments
	}
	if len(mail.To) > 50 { // maximum allowed recipients
		return nil, types.ErrTooManyRecipients
	}
	if mail.Subject == "" && mail.BodyHTML == "" && mail.BodyText == "" {
		// ApiErrorf(c, http.StatusBadRequest, "no subject or body")
		return nil, types.ErrBadRequestMissingSubjectOrBody
	}
	// add to queue
	task := &types.SmtpTask{
		Mail:    mail,
		Address: up.ID,
	}
	sendTask, tErr := types.NewSmtpCommSendTask(task)
	if tErr != nil {
		return nil, tErr
	}
	mail.Timestamp = time.Now().UTC().UnixMilli()

	id, idErr := util.SmtpMailToUniqueID(mail, types.MailioFolderSent)
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
func (ma *MessagingApi) sendDIDCommMessage(senderAddress string, input types.DIDCommMessage) (*string, error) {
	// validate input
	if len(input.To) == 0 && len(input.ToEmails) == 0 {
		return nil, types.ErrNoRecipient
	}
	if len(input.ToEmails) > 50 { // maximum allowed recipients
		return nil, types.ErrTooManyRecipients
	}
	if len(input.EncryptedBody.Ciphertext) > 3*1024*1024 { // maximum total allowed size
		return nil, types.ErrMessageTooLarge
	}
	if len(input.EncryptedAttachments) > 50 { // maximum allowed attachments
		return nil, types.ErrTooManyAttachments
	}

	// default is messaging
	if input.Intent == "" {
		input.Intent = types.DIDCommIntentMessage
	}

	// Ensure the 'from' field is set to the subject address and it's coming from this server
	from := fmt.Sprintf("did:web:%s#%s", global.Conf.Mailio.ServerDomain, senderAddress)
	if input.From != from {
		return nil, types.ErrNotAuthorized
	}

	// intended folder for sender is "sent"
	id, idErr := util.DIDDocumentToUniqueID(&input, types.MailioFolderSent)
	if idErr != nil {
		global.Logger.Log(idErr.Error(), "failed to create unique id")
		return nil, types.ErrInternal
	}
	input.ID = id
	input.CreatedTime = time.Now().UTC().UnixMilli()

	task := &types.Task{
		Address:        senderAddress,
		DIDCommMessage: &input,
	}
	sendTask, tErr := types.NewDIDCommSendTask(task)
	if tErr != nil {
		global.Logger.Log(tErr.Error(), "failed to create task")
		return nil, types.ErrInternal
	}

	taskInfo, tqErr := ma.env.TaskClient.Enqueue(sendTask,
		asynq.MaxRetry(3),             // max number of times to retry the task
		asynq.Timeout(60*time.Second), // max time to process the task
		asynq.TaskID(input.ID),        // unique task id
		asynq.Unique(time.Second*10))  // unique for 10 seconds (preventing multiple equal messages in the queue)
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
		ApiErrorf(c, http.StatusUnprocessableEntity, "no recipient")
	case types.ErrNotAuthorized:
		ApiErrorf(c, http.StatusForbidden, "not authorized to send from this email address")
	case types.ErrMessageTooLarge:
		ApiErrorf(c, http.StatusRequestEntityTooLarge, "message too large")
	case types.ErrTooManyAttachments:
		ApiErrorf(c, http.StatusUnprocessableEntity, "too many attachments")
	case types.ErrTooManyRecipients:
		ApiErrorf(c, http.StatusUnprocessableEntity, "too many recipients")
	case types.ErrBadRequestMissingSubjectOrBody:
		ApiErrorf(c, http.StatusUnprocessableEntity, "missing subject or body")
	default:
		ApiErrorf(c, http.StatusInternalServerError, "failed to send message")
	}
	global.Logger.Log(err.Error(), "failed to send message")
}
