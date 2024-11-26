package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type HandshakeApi struct {
	handshakeService   *services.HandshakeService
	nonceService       *services.NonceService
	mtpService         *services.MtpService
	userService        *services.UserService
	userProfileService *services.UserProfileService
	ssiService         *services.SelfSovereignService
	validate           *validator.Validate
}

func NewHandshakeApi(handshakeService *services.HandshakeService, nonceService *services.NonceService, mtpService *services.MtpService, userService *services.UserService, userProfileService *services.UserProfileService) *HandshakeApi {
	return &HandshakeApi{
		handshakeService:   handshakeService,
		nonceService:       nonceService,
		mtpService:         mtpService,
		userProfileService: userProfileService,
		userService:        userService,
		validate:           validator.New(),
	}
}

// // Get Handshake Stats
// // @Security Bearer
// // @Summary Get handshake statistics
// // @Description Returns the stats for the recipient in the past 3 months
// // @Tags Handshake
// // @Param from query string true "recipient (email hash or address)"
// // @Success 200 {object} types.Handshake
// // @Accept json
// // @Produce json
// // @Router /api/v1/handshakestats [get]
// func (ha *HandshakeApi) GetHandshakeStats(c *gin.Context) {

// 	// extract address from JWS token
// 	address, exists := c.Get("subjectAddress")
// 	if !exists {
// 		ApiErrorf(c, http.StatusInternalServerError, "jwt invalid")
// 		return
// 	}

// 	// thisUserDID, err := ha.ssiService.GetDIDDocument(address.(string))
// 	// if err != nil {
// 	// 	global.Logger.Log(err.Error(), "failed to get DID document", address)
// 	// 	ApiErrorf(c, http.StatusInternalServerError, "failed to get DID document")
// 	// 	return
// 	// }

// 	from := c.Query("from") // can be mailio address or scrypt email address

// 	receivedAll := 0
// 	receivedRead := 0
// 	sent := 0

// 	toTimestamp := time.Now().UnixMilli()
// 	currentTime := time.UnixMilli(toTimestamp)
// 	sixMonthsAgo := currentTime.AddDate(0, -3, 0)
// 	fromTimestamp := sixMonthsAgo.UnixMilli() // 3 months ago

// 	// count the number of sent messages to the recipient email or Mailio address
// 	countSent, csErr := ha.userService.CountNumberOfSentByRecipientMessages(address.(string), from, fromTimestamp, toTimestamp)
// 	if csErr != nil {
// 		global.Logger.Log("error counting number of sent messages to email", csErr.Error())
// 	} else {
// 		if len(countSent.Rows) > 0 {
// 			sent = countSent.Rows[0].Value
// 		}
// 	}

// 	// count number of received messages from the sender
// 	isReadCountReceivedAll := false
// 	countReceivedAll, crErr := ha.userService.CountNumberOfMessages(address.(string), from, "", &isReadCountReceivedAll, fromTimestamp, toTimestamp)
// 	// count number of received messages from the sender that are read
// 	isReadCountReceivedRead := true
// 	countReceivedRead, crrErr := ha.userService.CountNumberOfMessages(address.(string), from, "", &isReadCountReceivedRead, fromTimestamp, toTimestamp)
// 	if errors.Join(crErr, crrErr) != nil {
// 		global.Logger.Log("error counting number of received messages", errors.Join(crErr, crrErr).Error())
// 	} else {
// 		receivedAll = util.SumUpItemsFromFolderCountResponse([]string{types.MailioFolderInbox, types.MailioFolderArchive, types.MailioFolderGoodReads, types.MailioFolderOther, types.MailioFolderTrash}, countReceivedAll)
// 		receivedRead = util.SumUpItemsFromFolderCountResponse([]string{types.MailioFolderInbox, types.MailioFolderArchive, types.MailioFolderGoodReads, types.MailioFolderOther, types.MailioFolderTrash}, countReceivedRead)
// 	}

// 	readVsReceived := global.Conf.Mailio.ReadVsReceived

// 	// ratio of read messages vs all received messages
// 	ratio := 0.0
// 	if receivedAll != 0 {
// 		ratio = float64(receivedRead) / float64(receivedAll)
// 	}
// 	// if more than X% of the messages are read, then store in goodreads
// 	ratioThreshold := float64(readVsReceived) / 100.0

// 	c.JSON(http.StatusOK, gin.H{
// 		"sent":                        sent,
// 		"receivedAll":                 receivedAll,
// 		"receivedRead":                receivedRead,
// 		"ratioReceivedReadVsReceived": ratio,
// 		"thresholdReadVsReceived":     ratioThreshold,
// 	})

// }

// // Get Handshake method
// // @Security Bearer
// // @Summary Get handshake by id
// // @Description Returns a single handshake by id
// // @Tags Handshake
// // @Param id path string true "Handshake ID"
// // @Success 200 {object} types.Handshake
// // @Accept json
// // @Produce json
// // @Router /api/v1/handshake/{id} [get]
// func (ha *HandshakeApi) GetHandshake(c *gin.Context) {
// 	id := c.Param("id")
// 	if id == "" {
// 		ApiErrorf(c, http.StatusBadRequest, "invalid id: %s", id)
// 		return
// 	}
// 	handshake, err := ha.handshakeService.GetByID(id)
// 	if err != nil {
// 		if err == types.ErrNotFound {
// 			ApiErrorf(c, http.StatusNotFound, "handshake not found: %s", id)
// 			return
// 		}
// 		ApiErrorf(c, http.StatusInternalServerError, "error while getting handshake: %s", err)
// 		return
// 	}

// 	c.JSON(http.StatusOK, util.StoredHandshakeToModelHandsake(handshake))
// }

// // Lookup handshake is public and looksup handshake by ownerAddress and sender scrypted email address or mailio address
// // @Summary Lookup handshake by ownerAddress and sender scrypted (hashed) address (or mailio address)
// // @Description Lookup handshake is public and looksup handshake by ownerAddress and sender scrypted (hashed) address or mailio address. If nothing found default server handshake returned
// // @Tags Handshake
// // @Param ownerAddress path string true "Owners mailio address"
// // @Param senderAddress path string true "Senders scrypt address or Mailio address"
// // @Success 200 {object} types.Handshake
// // @Accept json
// // @Produce json
// // @Router /api/v1/handshake/lookup/{ownerAddress}/{senderAddress} [get]
// func (ha *HandshakeApi) LookupHandshake(c *gin.Context) {
// 	ownerAddress := c.Param("ownerAddress")
// 	senderAddress := c.Param("senderAddress")
// 	if ownerAddress == "" || senderAddress == "" {
// 		ApiErrorf(c, http.StatusBadRequest, "invalid address: %s/%s", ownerAddress, senderAddress)
// 		return
// 	}

// 	handshake, err := ha.handshakeService.GetByMailioAddress(ownerAddress, senderAddress)
// 	if err != nil {
// 		// cannot be not found (default handshake should be returned)
// 		ApiErrorf(c, http.StatusInternalServerError, "error while getting handshake: %s", err)
// 		return
// 	}
// 	c.JSON(http.StatusOK, util.StoredHandshakeToModelHandsake(handshake))
// }

// // List logged in users handshake
// // @Security Bearer
// // @Summary List handshakes (default 10 results)
// // @Description List all handshakes
// // @Tags Handshake
// // @Param limit query integer false "max number of results"
// // @Param bookmark query string false "paging token"
// // @Success 200 {object} types.PagingResults
// // @Failure 401 {object} api.ApiError "not authorized"
// // @Failure 429 {object} api.ApiError "rate limit exceeded"
// // @Accept json
// // @Produce json
// // @Router /api/v1/handshake [get]
// func (ha *HandshakeApi) ListHandshakes(c *gin.Context) {
// 	// extract address from JWS token
// 	address, exists := c.Get("subjectAddress")
// 	if !exists {
// 		ApiErrorf(c, http.StatusInternalServerError, "jwt invalid")
// 		return
// 	}
// 	limitStr := c.DefaultQuery("limit", "10")
// 	limit, err := strconv.Atoi(limitStr)
// 	if err != nil {
// 		ApiErrorf(c, http.StatusBadRequest, "invalid limit: %s", limitStr)
// 		return
// 	}
// 	bookmark := c.DefaultQuery("bookmark", "")
// 	handshakes, err := ha.handshakeService.ListHandshakes(address.(string), bookmark, limit)
// 	if err != nil {
// 		ApiErrorf(c, http.StatusInternalServerError, "error while fetching handshakes: %s", err.Error())
// 		return
// 	}
// 	c.JSON(http.StatusOK, handshakes)
// }

// // Create Handshake method
// // @Security Bearer
// // @Summary Create a new handshake
// // @Description Create a new handshake
// // @Tags Handshake
// // @Accept json
// // @Produce json
// // @Param handshake body types.Handshake true "Handshake"
// // @Success 201 {object} types.Handshake
// // @Failure 401 {object} api.ApiError "invalid signature/not authorized"
// // @Failure 400 {object} api.ApiError "bad request"
// // @Failure 429 {object} api.ApiError "rate limit exceeded"
// // @Router /api/v1/handshake [post]
// func (ha *HandshakeApi) CreateHandshake(c *gin.Context) {
// 	// Get the request body and decode it into a Handshake struct
// 	var handshake types.Handshake
// 	if err := c.ShouldBindJSON(&handshake); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 		return
// 	}
// 	pubKey, exists := c.Get("usrPubKey")
// 	if !exists {
// 		ApiErrorf(c, http.StatusUnauthorized, "jwt invalid")
// 		return
// 	}

// 	sErr := ha.handshakeService.Save(&handshake, pubKey.(string))
// 	if sErr != nil {
// 		if sErr == types.ErrSignatureInvalid {
// 			ApiErrorf(c, http.StatusUnauthorized, "invalid signature")
// 			return
// 		}
// 		ApiErrorf(c, http.StatusBadRequest, "failed to store handhake")
// 		return
// 	}

// 	// Return the created handshake
// 	c.JSON(http.StatusCreated, handshake)
// }

// // Update Handshake method
// // @Security Bearer
// // @Summary Update a handshake
// // @Description Update a handshake
// // @Tags Handshake
// // @Accept json
// // @Produce json
// // @Param id path string true "Handshake ID"
// // @Param handshake body types.Handshake true "Handshake"
// // @Success 200 {object} types.Handshake
// // @Failure 401 {object} api.ApiError "not authorized"
// // @Failure 429 {object} api.ApiError "rate limit exceeded"
// // @Router /api/v1/handshake/{id} [put]
// func (ha *HandshakeApi) UpdateHandshake(c *gin.Context) {
// 	var handshake types.Handshake
// 	if err := c.ShouldBindJSON(&handshake); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 		return
// 	}
// 	//TODO! finish this

// 	// Get the handshake with the given id
// 	// if err := ha.DB.First(&handshake, c.Param("id")).Error; err != nil {
// 	// 	c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found!"})
// 	// 	return
// 	// }

// 	// Update the handshake
// 	// ha.DB.Save(&handshake)

// 	// Return handshake
// 	c.JSON(http.StatusOK, handshake)
// }

// // Delete Handshake method
// // @Security Bearer
// // @Summary Delete a handshake
// // @Description Delete a handshake
// // @Tags Handshake
// // @Param id path string true "Handshake ID"
// // @Success 204
// // @Failure 401 {object} api.ApiError "not authorized"
// // @Failure 429 {object} api.ApiError "rate limit exceeded"
// // @Router /api/v1/handshake/{id} [delete]
// func (ha *HandshakeApi) DeleteHandshake(c *gin.Context) {
// 	id := c.Param("id")
// 	if id == "" {
// 		ApiErrorf(c, http.StatusBadRequest, "invalid id: %s", id)
// 		return
// 	}
// 	//TODO! finish this
// 	// delete the handshake with given id
// 	// ha.DB.Delete(&types.Handshake{}, id)
// 	c.Status(http.StatusNoContent)
// }

// Personal Handshake link
// @Security Bearer
// @Summary Create personal handshake link
// @Description Create personal handshake link
// @Tags Handshake
// @Success 200 {object} types.HandshakeLink
// @Failure 401 {object} api.ApiError "not authorized"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/handshakeoffer [get]
func (ha *HandshakeApi) PersonalHandshakeLink(c *gin.Context) {
	// extract address from JWS token
	address, exists := c.Get("subjectAddress")
	if !exists {
		ApiErrorf(c, http.StatusUnauthorized, "not authorized to create personal handshake")
		return
	}
	// create a personal handshake link
	profile, pErr := ha.userProfileService.Get(address.(string))
	if pErr != nil {
		ApiErrorf(c, http.StatusNotFound, "user profile not found")
		return
	}

	// domain := global.Conf.Mailio.Domain
	// nonces are typically deleted within 5 minutes. That should be enough time to use the link
	nonce, nErr := ha.nonceService.CreateCustomNonce(16)
	if nErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "error while creating nonce")
		return
	}

	// create a link with the nonce
	// format: nonce:web:domain:address
	link := types.HandshakeLink{
		Link: nonce.Nonce + ":web:" + profile.Domain + ":" + address.(string),
	}
	c.JSON(http.StatusOK, link)
}

// Request handshake from origin server (digitally signed) if missing in local database
// @Security Bearer
// @Summary Request handshake from origin server (digitally signed) if missing in local database
// @Description Request handshake from origin server (digitally signed)
// @Tags Handshake
// @Accept json
// @Produce json
// @Param handshake body types.InputHandshakeLookup true "InputHandshakeLookup"
// @Success 200 {object} types.HandshakeLookupResponse
// @Failure 401 {object} api.ApiError "invalid signature"
// @Failure 400 {object} api.ApiError "bad request"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/handshakefetch [post]
func (hs *HandshakeApi) HandshakeFetch(c *gin.Context) {
	// get logged in users address
	address, exists := c.Get("subjectAddress")
	if !exists {
		ApiErrorf(c, http.StatusBadRequest, "not authorized")
		return
	}
	// get the request body and decode it into a InputHandshakeLookup struct
	var handshakeLookup types.InputHandshakeLookup
	if err := c.ShouldBindJSON(&handshakeLookup); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// validate the input
	err := hs.validate.Struct(handshakeLookup)
	if err != nil {
		msg := util.ValidationErrorToMessage(err)
		ApiErrorf(c, http.StatusBadRequest, msg)
		return
	}

	foundHandshakes, notFoundLookups, hErr := hs.mtpService.LookupHandshakes(address.(string), handshakeLookup.Lookups)
	if hErr != nil {
		ApiErrorf(c, http.StatusBadRequest, "failed to request handshake")
		return
	}
	//TODO: save handshakes (for caching)

	lookupResponse := types.HandshakeLookupResponse{
		Found:    foundHandshakes,
		NotFound: notFoundLookups,
	}

	c.JSON(http.StatusOK, lookupResponse)
}
