package api

import (
	"net/http"
	"net/mail"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type DomainApi struct {
	allDomains    []types.UserDomain
	validate      *validator.Validate
	domainService *services.DomainService
}

func NewDomainApi(domainService *services.DomainService) *DomainApi {
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
		allDomains:    all,
		validate:      validator.New(),
		domainService: domainService,
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

// Resolve domain from email address
// @Summary Resolve domain from email address (smtp or mailio)
// @Security Bearer
// @Description Identify if an email is a DIDcomm/Mailio or SMTP address, and resolve the DID if it’s from a Mailio server.
// @Tags Messaging
// @Accept json
// @Produce json
// @Param email query string true "valid email address"
// @Success 200 {object} types.Domain
// @Failure 400 {object} api.ApiError "bad request"
// @Failure 401 {object} api.ApiError "invalid signature or unauthorized to send messages"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/resolve/domain [get]
func (ma *DomainApi) ResolveDomainForEmail(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		ApiErrorf(c, http.StatusBadRequest, "email address is required")
		return
	}
	parsedEmail, pErr := mail.ParseAddress(email)
	if pErr != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid email address")
		return
	}
	domain := strings.Split(parsedEmail.Address, "@")[1]
	// check if there is already a record of this domain
	domainObj, err := ma.domainService.ResolveDomain(domain)
	if err != nil {
		ApiErrorf(c, http.StatusServiceUnavailable, "error resolving domain. try again later")
		return
	}
	c.JSON(http.StatusOK, domainObj)
}
