package interceptors

import (
	"net"
	"strings"

	"github.com/gin-gonic/gin"
)

func getIP(c *gin.Context) (*string, error) {
	ip := c.Request.Header.Get("X-Real-IP")
	if len(ip) > 0 {
		return &ip, nil
	}

	ip = c.Request.Header.Get("CloudFront-Forwarded-Proto")
	if len(ip) > 0 {
		return &ip, nil
	}

	ip = c.Request.Header.Get("X-Forwarded-For")
	ipList := strings.Split(ip, ",")
	if len(ipList[0]) > 0 {
		return &ipList[0], nil
	}

	// If there is no "X-Real-IP", "CloudFront-Forwarded-Proto" or "X-Forwarded-For", get IP from "RemoteAddr"
	ip, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		return nil, err
	}
	return &ip, nil
}
