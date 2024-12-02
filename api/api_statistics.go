package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

// APIStatistics is the API for checking number of received emails from sender and an interest recipient showed for the senders emails
type APIStatistics struct {
	statisticsService *services.StatisticsService
	validate          *validator.Validate
}

func NewAPIStatistics(statisticsService *services.StatisticsService) *APIStatistics {
	return &APIStatistics{statisticsService: statisticsService, validate: validator.New()}
}

// Get Email statistics
// @Security Bearer
// @Summary Get Email statistics
// @Description Returns number of sent emails, received emails and interest shown by the recipient
// @Tags Statistics
// @Param sender query string true "Sender email address or Mailio address"
// @Success 200 {object} types.EmailStatisticsOutput
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Accept json
// @Produce json
// @Router /api/v1/emailstatistics [get]
func (a *APIStatistics) GetEmailStatistics(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	address := c.GetString("subjectAddress")
	if address == "" {
		ApiErrorf(c, http.StatusUnauthorized, "address not found")
		return
	}

	sender := c.Query("sender")
	if sender == "" {
		ApiErrorf(c, http.StatusBadRequest, "sender required")
		return
	}

	statsReceived, sErr := a.statisticsService.GetEmailStatistics(ctx, sender, address)
	if sErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to get email statistics: %s", sErr.Error())
		return
	}
	statsSent, sErr := a.statisticsService.GetEmailStatistics(ctx, address, sender)
	if sErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to get email statistics: %s", sErr.Error())
		return
	}
	interestCount, iErr := a.statisticsService.GetEmailInterest(ctx, sender, address)
	if iErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to get email interest: %s", iErr.Error())
		return
	}

	senyByDay, sErr := a.statisticsService.GetEmailSentByDay(ctx, address, time.Now().UTC().Truncate(24*time.Hour).Unix())
	if sErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to get email sent by day: %s", sErr.Error())
		return
	}

	output := types.EmailStatisticsOutput{
		Received:  statsReceived,
		Sent:      statsSent,
		Interest:  interestCount,
		SentByDay: senyByDay,
	}

	c.JSON(http.StatusOK, output)
}

// Reporting interest shown by the recipient
// @Security Bearer
// @Summary Report Interest
// @Description Report interest shown by the recipient (e.g. clicking on a link in the email, reading an email, archiving it, ...)
// @Tags Statistics
// @Param interest body types.InterestInput true "interest shown by the recipient"
// @Success 200 {object} types.InterestOuput
// @Failure 400 {object} api.ApiError "bad request"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Accept json
// @Produce json
// @Router /api/v1/emailstatistics/interest [put]
func (a *APIStatistics) ReportInterest(c *gin.Context) {
	address := c.GetString("subjectAddress")
	if address == "" {
		ApiErrorf(c, http.StatusUnauthorized, "address not found")
		return
	}

	var senderInput types.InterestInput
	if err := c.ShouldBindJSON(&senderInput); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := a.validate.Struct(senderInput)
	if err != nil {
		msg := util.ValidationErrorToMessage(err)
		ApiErrorf(c, http.StatusBadRequest, msg)
		return
	}

	iErr := a.statisticsService.ProcessEmailInterest(senderInput.Sender, address, senderInput.MessageId)
	if iErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to process email interest %s", iErr.Error())
		return
	}

	c.JSON(http.StatusAccepted, types.InterestOuput{MessageId: senderInput.MessageId})

}

// Test Email statistics
// @Security Bearer
// @Summary Get Email statistics
// @Description Returns number of sent emails, received emails and interest shown by the recipient
// @Tags Statistics
// @Param sender query string true "Sender email address or Mailio address"
// @Success 200 {object} types.OutputBasicUserInfo
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Accept json
// @Produce json
// @Router /api/v1/teststats [get]
func (a *APIStatistics) TestEmailStatistics(c *gin.Context) {

	address := c.GetString("subjectAddress")
	if address == "" {
		ApiErrorf(c, http.StatusUnauthorized, "address not found")
		return
	}

	sender := c.Query("sender")
	if sender == "" {
		ApiErrorf(c, http.StatusBadRequest, "sender required")
		return
	}

	peOneErr := a.statisticsService.ProcessEmailStatistics(sender, address)
	peTwoErr := a.statisticsService.ProcessEmailStatistics(address, sender)
	if errors.Join(peOneErr, peTwoErr) != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to process email statistics: %s", errors.Join(peOneErr, peTwoErr).Error())
		return
	}
	iErr := a.statisticsService.ProcessEmailInterest(sender, address, "test")
	if iErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to process email interest %s", iErr.Error())
		return
	}
	sErr := a.statisticsService.ProcessEmailsSentStatistics(address)
	if sErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to process email sent statistics %s", sErr.Error())
		return
	}

	// Flushing the cache
	a.statisticsService.FlushEmailInterests()
	a.statisticsService.FlushEmailStatistics()
	a.statisticsService.FlushSentEmailStatistics()

}
