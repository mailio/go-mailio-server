package api

import (
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/mailio/go-mailio-server/util"
)

type DomainApi struct {
	allDomains []string
	validate   *validator.Validate
}

func NewDomainApi() *DomainApi {
	// take all configured domains
	return &DomainApi{
		allDomains: util.ListDomains(),
	}
}

// List of supported domains
// @Summary List all domains
// @Description Returns a list of all supported domains
// @Tags Domains
// // @Success 200 {object} []string
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Failure 500 {object} api.ApiError "error creating server did"
// @Accept json
// @Produce json
// @Router /api/v1/domains [get]
func (da *DomainApi) List(c *gin.Context) {
	all := da.allDomains
	c.JSON(200, gin.H{"domains": all})
}
