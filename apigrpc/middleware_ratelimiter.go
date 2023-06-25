package apigrpc

import (
	"context"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/ratelimit"
	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/time/rate"
)

const MAX_REQUESTS_PER_SECOND = 5

// GrpcRateLimiter limiter implements Limiter interface.
// it uses
type GrpcRateLimiter struct {
	rl    ratelimit.Limiter
	cache *lru.Cache[string, *rate.Limiter]
}

func NewGrpcRateLimiter() *GrpcRateLimiter {
	cache, cErr := lru.New[string, *rate.Limiter](1000)
	if cErr != nil {
		panic(cErr)
	}
	return &GrpcRateLimiter{
		cache: cache,
	}
}

func (grpcRl *GrpcRateLimiter) Limit(ctx context.Context, authority string) bool {
	if rl, ok := grpcRl.cache.Get(authority); ok {
		return rl.Allow()
	}
	rl := rate.NewLimiter(rate.Every(time.Second), MAX_REQUESTS_PER_SECOND)
	grpcRl.cache.Add(authority, rl)
	return rl.Allow()
}
