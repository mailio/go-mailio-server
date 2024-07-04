package interceptors

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis_rate/v10"
	apiutil "github.com/mailio/go-mailio-server/api/util"
	"github.com/mailio/go-mailio-server/global"
)

const (
	LimitRequestsPerSecond     = 5
	LimitRequestNoncePerSecond = 1
)

func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip, ipErr := apiutil.GetIPFromContext(c)
		if ipErr != nil {
			// ignore for now
		}
		if ip == nil {
			unkn := "unknown"
			ip = &unkn
		}
		userAgent := c.GetHeader("User-Agent")
		acceptLanguage := c.GetHeader("Accept-Language")
		referer := c.GetHeader("Referer")
		cookies := c.Request.Cookies()
		all := fmt.Sprintf("%s%s%s%s", *ip, userAgent, acceptLanguage, referer)
		// Iterate through cookies
		for _, cookie := range cookies {
			all = fmt.Sprintf("%s%s%s", all, cookie.Name, cookie.Value)
		}

		limit := LimitRequestsPerSecond

		re := regexp.MustCompile("^/api/v.*/nonce$")
		if re.MatchString(c.Request.URL.Path) {
			limit = LimitRequestNoncePerSecond
			all = fmt.Sprintf("%s%s", all, "_nonce")
		}

		hash := xxhash.Sum64String(all)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()

		result, err := global.RateLimiter.Allow(ctx, strconv.FormatUint(hash, 10), redis_rate.PerSecond(limit))
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, errors.New("failed to perform rate limit check"))
			return
		}
		if result.Allowed <= 0 {
			c.AbortWithError(http.StatusTooManyRequests, errors.New("too many requests"))
			return
		}

		c.Writer.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit.Rate))
		c.Writer.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
		c.Writer.Header().Set("X-RateLimit-Reset", strconv.Itoa(int(result.ResetAfter.Milliseconds())))
		c.Next()
	}
}
