package interceptors

import (
	"context"

	"golang.org/x/net/idna"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Limiter defines the interface to perform request rate limiting.
// If Limit function return true, the request will be rejected.
// Otherwise, the request will pass.
type RateLimiter interface {
	Limit(ctx context.Context, authority string) bool
}

// UnaryServerInterceptor returns a new unary server interceptors that performs request rate limiting.
func UnaryServerRatelimitInterceptor(rate RateLimiter) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// extract required headers from the context
		authorityDomain := ""
		if meta, ok := metadata.FromIncomingContext(ctx); ok {
			auth := meta[":authority"]
			if len(auth) > 0 {
				authorityDomain = auth[0]
			}
		}

		// check if the authority is valid
		if authorityDomain == "" {
			return nil, status.Error(codes.InvalidArgument, "authority domain is empty. Please set the :authority header with your domain name (e.g. example.com)")
		}
		host, err := idna.Lookup.ToASCII(authorityDomain)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "authority domain is invalid. Please set the :authority header with your domain name (e.g. example.com): %v", err)
		}
		isAllowed := rate.Limit(ctx, host)
		if !isAllowed {
			return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}
		return handler(ctx, req)
	}
}
