package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mailio/go-mailio-server/global"
)

type HealthCheckAPI struct {
}

func NewHealthCheckAPI() *HealthCheckAPI {
	return &HealthCheckAPI{}
}

func (ha *HealthCheckAPI) HealthCheck(c *gin.Context) {
	version := global.Conf.Version
	mode := global.Conf.Mode
	emailDomain := global.Conf.Mailio.EmailDomain
	c.JSON(http.StatusOK, gin.H{"status": "ok", "version": version, "mode": mode, "domain": emailDomain})
}
