package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
)

type HandshakeApi struct {
	handshakeService *services.HandshakeService
	nonceService     *services.NonceService
}

func NewHandshakeApi(handshakeService *services.HandshakeService, nonceService *services.NonceService) *HandshakeApi {
	return &HandshakeApi{
		handshakeService: handshakeService,
		nonceService:     nonceService,
	}
}

// Get Handshake method
// @Security Bearer
// @Summary Get handshake by id
// @Description Returns a single handshake by id
// @Tags Handshake
// @Param id path string true "Handshake ID"
// @Success 200 {object} types.Handshake
// @Accept json
// @Produce json
// @Router /api/v1/handshake/{id} [get]
func (ha *HandshakeApi) GetHandshake(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		ApiErrorf(c, http.StatusBadRequest, "invalid id: %s", id)
		return
	}
	handshake, err := ha.handshakeService.GetByID(id)
	if err != nil {
		if err == types.ErrNotFound {
			ApiErrorf(c, http.StatusNotFound, "handshake not found: %s", id)
			return
		}
		ApiErrorf(c, http.StatusInternalServerError, "error while getting handshake: %s", err)
		return
	}
	c.JSON(http.StatusOK, handshake)
}

// Lookup handshake is public and looksup handshake by ownerAddress and sender scrypted email address or mailio address
// @Summary Lookup handshake by ownerAddress and sender scrypted (hashed) address (or mailio address)
// @Description Lookup handshake is public and looksup handshake by ownerAddress and sender scrypted (hashed) address or mailio address. If nothing found default server handshake returned
// @Tags Handshake
// @Param ownerAddress path string true "Owners mailio address"
// @Param senderAddress path string true "Senders scrypt address or Mailio address"
// @Success 200 {object} types.Handshake
// @Accept json
// @Produce json
// @Router /api/v1/handshake/lookup/{ownerAddress}/{senderAddress} [get]
func (ha *HandshakeApi) LookupHandshake(c *gin.Context) {
	ownerAddress := c.Param("ownerAddress")
	senderAddress := c.Param("senderAddress")
	if ownerAddress == "" || senderAddress == "" {
		ApiErrorf(c, http.StatusBadRequest, "invalid address: %s/%s", ownerAddress, senderAddress)
		return
	}

	handshake, err := ha.handshakeService.GetByMailioAddress(ownerAddress, senderAddress)
	if err != nil {
		// cannot be not found (default handshake should be returned)
		ApiErrorf(c, http.StatusInternalServerError, "error while getting handshake: %s", err)
		return
	}
	c.JSON(http.StatusOK, handshake)
}

// List logged in users handshake
// @Security Bearer
// @Summary List handshakes (default 10 results)
// @Description List all handshakes
// @Tags Handshake
// @Param limit query integer false "max number of results"
// @Param bookmark query string false "paging token"
// @Success 200 {object} types.PagingResults
// @Accept json
// @Produce json
// @Router /api/v1/handshake [get]
func (ha *HandshakeApi) ListHandshakes(c *gin.Context) {
	// extract address from JWS token
	address, exists := c.Get("subjectAddress")
	if !exists {
		ApiErrorf(c, http.StatusInternalServerError, "jwt invalid")
		return
	}
	limitStr := c.DefaultQuery("limit", "10")
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid limit: %s", limitStr)
		return
	}
	bookmark := c.DefaultQuery("bookmark", "")
	handshakes, err := ha.handshakeService.ListHandshakes(address.(string), bookmark, limit)
	if err != nil {
		ApiErrorf(c, http.StatusInternalServerError, "error while fetching handshakes: %s", err.Error())
		return
	}
	c.JSON(http.StatusOK, handshakes)
}

// Create Handshake method
// @Security Bearer
// @Summary Create a new handshake
// @Description Create a new handshake
// @Tags Handshake
// @Accept json
// @Produce json
// @Param handshake body types.Handshake true "Handshake"
// @Success 201 {object} types.Handshake
// @Failure 401 {object} api.ApiError "invalid signature"
// @Failure 400 {object} api.ApiError "bad request"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/handshake [post]
func (ha *HandshakeApi) CreateHandshake(c *gin.Context) {
	// Get the request body and decode it into a Handshake struct
	var handshake types.Handshake
	if err := c.ShouldBindJSON(&handshake); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	pubKey, exists := c.Get("usrPubKey")
	if !exists {
		ApiErrorf(c, http.StatusUnauthorized, "jwt invalid")
		return
	}

	sErr := ha.handshakeService.Save(&handshake, pubKey.(string))
	if sErr != nil {
		if sErr == types.ErrSignatureInvalid {
			ApiErrorf(c, http.StatusUnauthorized, "invalid signature")
			return
		}
		ApiErrorf(c, http.StatusBadRequest, "failed to store handhake")
		return
	}

	// Return the created handshake
	c.JSON(http.StatusCreated, handshake)
}

// Update Handshake method
// @Security Bearer
// @Summary Update a handshake
// @Description Update a handshake
// @Tags Handshake
// @Accept json
// @Produce json
// @Param id path string true "Handshake ID"
// @Param handshake body types.Handshake true "Handshake"
// @Success 200 {object} types.Handshake
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/handshake/{id} [put]
func (ha *HandshakeApi) UpdateHandshake(c *gin.Context) {
	var handshake types.Handshake
	if err := c.ShouldBindJSON(&handshake); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get the handshake with the given id
	// if err := ha.DB.First(&handshake, c.Param("id")).Error; err != nil {
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found!"})
	// 	return
	// }

	// Update the handshake
	// ha.DB.Save(&handshake)

	// Return handshake
	c.JSON(http.StatusOK, handshake)
}

// Delete Handshake method
// @Security Bearer
// @Summary Delete a handshake
// @Description Delete a handshake
// @Tags Handshake
// @Param id path string true "Handshake ID"
// @Success 204
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/handshake/{id} [delete]
func (ha *HandshakeApi) DeleteHandshake(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		ApiErrorf(c, http.StatusBadRequest, "invalid id: %s", id)
		return
	}
	// delete the handshake with given id
	// ha.DB.Delete(&types.Handshake{}, id)
	c.Status(http.StatusNoContent)
}

func (ha *HandshakeApi) PersonalHandshakeLink(c *gin.Context) {
	// extract address from JWS token
	address, exists := c.Get("subjectAddress")
	if !exists {
		ApiErrorf(c, http.StatusUnauthorized, "not authorized to create personal handshake")
		return
	}
	// create a personal handshake link
	domain := global.Conf.Mailio.Domain
	// nonces are typically deleted within 5 minutes. That should be enough time to use the link
	nonce, nErr := ha.nonceService.CreateCustomNonce(32)
	if nErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "error while creating nonce")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"link": nonce.Nonce + address.(string) + domain,
	})
}
