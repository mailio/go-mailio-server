package interceptors

import "github.com/gin-gonic/gin"

func Fido2Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}
