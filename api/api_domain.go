package api

import (
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	smtpmodule "github.com/mailio/go-mailio-server/email/smtp"
)

type DomainApi struct {
	allDomains []string
	validate   *validator.Validate
}

func NewDomainApi() *DomainApi {
	da := &DomainApi{
		validate: validator.New(),
	}
	for _, h := range smtpmodule.Handlers() {
		smtpHandler := smtpmodule.GetHandler(h)
		// list all domains from all smtp modules
		domains, err := smtpHandler.ListDomains()
		if err != nil {
			panic(err)
		}
		da.allDomains = append(da.allDomains, domains...)
	}
	// remove duplicates
	if len(da.allDomains) > 0 {
		slices.Sort(da.allDomains)
		da.allDomains = slices.Compact(da.allDomains)
	}
	return da
}

func (da *DomainApi) List(c *gin.Context) {
	all := da.allDomains
	c.JSON(200, gin.H{"domains": all})
}
