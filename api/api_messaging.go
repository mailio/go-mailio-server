package api

import (
	"encoding/base64"
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
// @Router /api/v1/didmessage [post]
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

	// default is messaging
	if input.Intent == "" {
		input.Intent = types.DIDCommIntentMessage
	}

	// validate input
	err := ma.validate.Struct(input)
	if err != nil {
		msg := util.ValidationErrorToMessage(err)
		ApiErrorf(c, http.StatusBadRequest, msg)
		return
	}

	// force the from field to be the subject address
	from := fmt.Sprintf("did:web:%s#%s", global.Conf.Mailio.Domain, subjectAddress.(string))
	if input.From != from {
		ApiErrorf(c, http.StatusUnauthorized, "unathorized")
		return
	}

	// intended folder for sender is "sent"
	id, idErr := util.DIDDocumentToUniqueID(&input, types.MailioFolderSent)
	if idErr != nil {
		ApiErrorf(c, http.StatusBadRequest, idErr.Error())
		return
	}
	input.ID = id
	input.CreatedTime = time.Now().UTC().UnixMilli()

	task := &types.Task{
		Address:        subjectAddress.(string),
		DIDCommMessage: &input,
	}
	sendTask, tErr := types.NewDIDCommSendTask(task)
	if tErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, tErr.Error())
		return
	}

	taskInfo, tqErr := ma.env.TaskClient.Enqueue(sendTask,
		asynq.MaxRetry(3),             // max number of times to retry the task
		asynq.Timeout(60*time.Second), // max time to process the task
		asynq.TaskID(input.ID),        // unique task id
		asynq.Unique(time.Second*10))  // unique for 10 seconds (preventing multiple equal messages in the queue)
	if tqErr != nil {
		global.Logger.Log(tqErr.Error(), "failed to send message")
		ApiErrorf(c, http.StatusInternalServerError, "failed to send message")
		return
	}
	global.Logger.Log(fmt.Sprintf("message sent: %s", taskInfo.ID), "message queued")

	c.JSON(http.StatusAccepted, types.DIDCommApiResponse{ID: input.ID})
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
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/smtp [post]
func (ma *MessagingApi) SendSmtpMessage(c *gin.Context) {
	var mail smtptypes.Mail
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

	// check daily sent limit (default = 10)
	fromTimestamp := time.Now().UTC().AddDate(0, 0, -1).UnixMilli()
	toTimestamp := time.Now().UTC().UnixMilli()
	countSent, csErr := ma.userService.CountNumberOfSentMessages(up.ID, fromTimestamp, toTimestamp)
	if csErr != nil {
		global.Logger.Log("error counting number of sent messages to email", csErr.Error())
	}
	sent := util.SumUpItemsFromFolderCountResponse([]string{types.MailioFolderSent}, countSent)
	if sent > 10 {
		ApiErrorf(c, http.StatusTooManyRequests, "24h limit exceeded")
		return
	}

	// validate if sender can send emails
	vsErr := ma.validateSmtpSender(c, mail.From.Address)
	if vsErr != nil {
		return
	}
	// validate input
	if mail.To == nil || len(mail.To) == 0 {
		ApiErrorf(c, http.StatusBadRequest, "no recipient")
		return
	}
	if mail.SizeBytes > 30*1024*1024 { // maximum total allowed size
		ApiErrorf(c, http.StatusBadRequest, "message too large")
		return
	}
	if len(mail.Attachments) > 100 { // maximum allowed attachments
		ApiErrorf(c, http.StatusBadRequest, "too many attachments")
		return
	}
	if len(mail.To) > 100 { // maximum allowed recipients
		ApiErrorf(c, http.StatusBadRequest, "too many recipients")
		return
	}
	if mail.Subject == "" && mail.BodyHTML == "" && mail.BodyText == "" {
		ApiErrorf(c, http.StatusBadRequest, "no subject or body")
		return
	}
	// add to queue
	task := &types.SmtpTask{
		Mail:    &mail,
		Address: up.ID,
	}
	sendTask, tErr := types.NewSmtpCommSendTask(task)
	if tErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, tErr.Error())
		return
	}
	mail.Timestamp = time.Now().UTC().UnixMilli()

	id, idErr := util.SmtpMailToUniqueID(&mail, types.MailioFolderSent)
	if idErr != nil {
		ApiErrorf(c, http.StatusBadRequest, idErr.Error())
		return
	}

	taskInfo, tqErr := ma.env.TaskClient.Enqueue(sendTask,
		asynq.MaxRetry(3),              // max number of times to retry the task
		asynq.Timeout(600*time.Second), // max time to process the task
		asynq.TaskID(id),               // unique task id
		asynq.ProcessIn(time.Second*time.Duration(taskDelaySeconds)), // delay processing for 5 seconds (user has time to cancel the smtp send)
		asynq.Unique(time.Second*10))                                 // unique for 10 seconds (preventing multiple equal messages in the queue)
	if tqErr != nil {
		global.Logger.Log(tqErr.Error(), "failed to send message")
		ApiErrorf(c, http.StatusInternalServerError, "failed to send message")
		return
	}
	global.Logger.Log(fmt.Sprintf("message SMTP sent: %s", taskInfo.ID), "message queued")

	c.JSON(http.StatusAccepted, types.DIDCommApiResponse{ID: id})

	// mime, mErr := mailiosmtp.ToMime(&mail, global.Conf.Mailio.Domain)
	// if mErr != nil {
	// 	ApiErrorf(c, http.StatusInternalServerError, "failed to create mime")
	// 	return
	// }
	// fmt.Printf("mime: %s\n", mime)
	// //TODO: support multiple domains (based on the FROM domain use the handler for instance)
	// mgHandler := mailiosmtp.GetHandler("mailgun")
	// if mgHandler == nil {
	// 	ApiErrorf(c, http.StatusInternalServerError, "failed to get mailgun handler")
	// 	return
	// }
	// id := "123"
	// // id, err := mgHandler.SendMimeMail(mime, mail.To)
	// // if err != nil {
	// // 	global.Logger.Log(err.Error(), "failed to send email")
	// // 	ApiErrorf(c, http.StatusInternalServerError, err.Error())
	// // 	return
	// // }
	// // log message sent id
	// global.Logger.Log(fmt.Sprintf("message sent: %s", id), "message sent")

	// tos := []string{}
	// for _, to := range mail.To {
	// 	tos = append(tos, to.String())
	// }
	// // store message in the database
	// mm := &types.MailioMessage{
	// 	ID:      id,
	// 	From:    mail.From.Address,
	// 	Folder:  types.MailioFolderSent,
	// 	Created: time.Now().UTC().UnixMilli(),
	// 	IsRead:  true, // send messages are read by default
	// 	DIDCommMessage: &types.DIDCommMessage{
	// 		Type:            "application/mailio-smtp+json",
	// 		ID:              id,
	// 		From:            mail.From.String(),
	// 		To:              tos,
	// 		Thid:            id,
	// 		CreatedTime:     time.Now().UTC().UnixMilli(),
	// 		Intent:          types.SMPTIntentMessage,
	// 		PlainBodyBase64: "", //TODO! create a plain message body (attachment references in s3, ...)
	// 	},
	// }
	// fmt.Printf("mm: %+v\n", mm)
	// //TODO: store id in the database
	// c.JSON(http.StatusAccepted, mail)
}

// check if user is honest about the from email address
// if not, return unauthorized
func (ma *MessagingApi) validateSmtpSender(c *gin.Context, fromEmailAddress string) error {
	scryptedMail, err := util.ScryptEmail(fromEmailAddress)
	if err != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to scrypt email address")
		return err
	}
	_, mErr := ma.userService.FindUserByScryptEmail(base64.URLEncoding.EncodeToString(scryptedMail))
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
