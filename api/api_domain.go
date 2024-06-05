package api

import (
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type DomainApi struct {
	allDomains []types.UserDomain
	validate   *validator.Validate
}

func NewDomainApi() *DomainApi {
	// take all configured domains
	allSmtp := util.ListSmtpDomains()
	allMailio := util.ListMailioDomains()
	all := []types.UserDomain{}
	for _, domain := range allSmtp {
		all = append(all, types.UserDomain{Name: domain, Type: "smtp"})
	}
	for _, domain := range allMailio {
		all = append(all, types.UserDomain{Name: domain, Type: "mailio"})
	}
	return &DomainApi{
		allDomains: all,
	}
}

// List of supported domains
// @Summary List all domains
// @Description Returns a list of all supported domains
// @Tags Domains
// @Success 200 {object} []types.UserDomain
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Failure 500 {object} api.ApiError "error creating server did"
// @Accept json
// @Produce json
// @Router /api/v1/domains [get]
func (da *DomainApi) List(c *gin.Context) {
	all := da.allDomains
	c.JSON(200, gin.H{"domains": all})
}
