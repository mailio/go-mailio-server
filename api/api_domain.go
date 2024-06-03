package api

import (
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	smtpmodule "github.com/mailio/go-mailio-server/email/smtp"
)

type DomainApi struct {
	validate *validator.Validate
}

func NewDomainApi() *DomainApi {
	for _, h := range smtpmodule.Handlers() {
		smtpHandler := smtpmodule.GetHandler(h)
		// TODO: needs get domains method
	}
	return &DomainApi{
		validate: validator.New(),
	}
}

func (da *DomainApi) List(c *gin.Context) {

}
