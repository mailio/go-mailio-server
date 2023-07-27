package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/mailio/go-mailio-core/did"
	coreErrors "github.com/mailio/go-mailio-core/errors"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
)

type VC struct {
	ssiService *services.SelfSovereignService
}

// new verifiable credential api
func NewVCApi(ssiService *services.SelfSovereignService) *VC {
	return &VC{
		ssiService: ssiService,
	}
}

// Get a verifiable credential by id
// @Security Bearer
// @Summary Get verifiable credential by id
// @Description Returns a single verifiable credential by id
// @Tags Verifiable Credentials
// @Param id path string true "VC ID"
// @Success 200 {object} did.VerifiableCredential
// @Failure 404 {object} api.ApiError "VC not found"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Failure 500 {object} api.ApiError "error creating server did"
// @Accept json
// @Produce json
// @Router /api/v1/credentials/{id} [get]
func (vc *VC) GetVC(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		ApiErrorf(c, http.StatusBadRequest, "id is required")
		return
	}
	output, err := vc.ssiService.GetVCByID(id)
	if err != nil {
		if err == coreErrors.ErrNotFound {
			ApiErrorf(c, http.StatusNotFound, "vc not found")
			return
		}
		ApiErrorf(c, http.StatusInternalServerError, "error getting vc")
		return
	}
	c.JSON(http.StatusOK, output)
}

func (vc *VC) UpdateVC(c *gin.Context) {
	// TODO! unfinished implementation
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

// Verify a verifiable credential
// @Security Bearer
// @Summary Verify a verifiable credential
// @Description Checks if signature is valid and returns a boolean object
// @Tags Verifiable Credentials
// @Param requestId path string true "Reference ID (request ID, could be anything)"
// @Param vc body did.VerifiableCredential true "Verifiable credential to verify"
// @Success 200 {object} types.VCValidationResponse
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Accept json
// @Produce json
// @Router /api/v1/credentials/{requestId}/verify [post]
func (vc *VC) VerifyVC(c *gin.Context) {
	reqId := c.Param("requestId")
	if reqId == "" {
		ApiErrorf(c, http.StatusBadRequest, "requestId is required")
		return
	}
	var didVC did.VerifiableCredential
	if err := c.ShouldBindJSON(&didVC); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	isValid, err := didVC.VerifyProof(global.PublicKey)
	if err != nil {
		ApiErrorf(c, http.StatusBadRequest, "failed to validate proof")
		return
	}
	resp := types.VCValidationResponse{
		Valid:     isValid,
		RequestId: reqId,
	}
	c.JSON(http.StatusOK, resp)
}

func (vc *VC) RevokeVC(c *gin.Context) {
	// TODO! unfinished implementation
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

// List of VCs
// @Summary List all VCs for a specific mailio address
// @Description Retruns a list of VCs by mailio address
// @Tags Verifiable Credentials
// @Security Bearer
// @Param address path string true "Mailio address"
// @Param limit query int false "Limit of VCs to return"
// @Param pageToken query string false "Page token"
// @Success 200 {object} did.Document
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Failure 500 {object} api.ApiError "error creating server did"
// @Accept json
// @Produce json
// @Router /api/v1/credentials/list/{address} [get]
func (vc *VC) ListVCs(c *gin.Context) {
	limitStr := c.Query("limit")
	address := c.Param("address")
	pageToken := c.Param("pageToken")
	limit := 10
	if limitStr != "" {
		l, err := strconv.Atoi(limitStr)
		if err != nil {
			ApiErrorf(c, http.StatusBadRequest, "invalid limit")
			return
		}
		limit = l
	}
	output, err := vc.ssiService.ListSubjectVCs(address, limit, pageToken)
	if err != nil {
		ApiErrorf(c, http.StatusInternalServerError, "error listing vcs")
		return
	}
	c.JSON(http.StatusOK, output)
}
