package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mailio/go-mailio-core/did"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
)

type VC struct {
}

// new verifiable credential api
func NewVCApi() *VC {
	return &VC{}
}

// Get a verifiable credential by id
// @Security Bearer
// @Summary Get verifiable credential by id
// @Description Returns a single verifiable credential by id
// @Tags Verifiable Credentials
// @Param id path string true "VC ID"
// @Success 200 {object} did.VerifiableCredential
// @Accept json
// @Produce json
// @Router /api/v1/credentials/{id} [get]
func (vc *VC) GetVC(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		ApiErrorf(c, http.StatusBadRequest, "id is required")
		return
	}
	newVc := did.NewVerifiableCredential("todo:finish:this")
	c.JSON(http.StatusOK, newVc)
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
