package interceptors

import (
	"context"

	"google.golang.org/grpc"
)

// Limiter defines the interface to perform request rate limiting.
// If Limit function return true, the request will be rejected.
// Otherwise, the request will pass.
type SignatureValidator interface {
	Validate(signature, payload []byte, publicKeyBase64 string) bool
}

// UnaryServerInterceptor returns a new unary server interceptors that performs request rate limiting.
func UnaryServerSignatureInterceptor(sigValidator SignatureValidator) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// extract required headers from the context
		// authorityDomain := ""
		// if meta, ok := metadata.FromIncomingContext(ctx); ok {
		// 	auth := meta[":authority"]
		// 	if len(auth) > 0 {
		// 		authorityDomain = auth[0]
		// 	}
		// }

		// // check if the authority is valid
		// if authorityDomain == "" {
		// 	return nil, status.Error(codes.InvalidArgument, "authority domain is empty. Please set the :authority header with your domain name (e.g. example.com)")
		// }
		// host, err := idna.Lookup.ToASCII(authorityDomain)
		// if err != nil {
		// 	return nil, status.Errorf(codes.InvalidArgument, "authority domain is invalid. Please set the :authority header with your domain name (e.g. example.com): %v", err)
		// }
		// // DNS check the host for (extracting the public key)
		// pk, pkErr := util.GetDNSMailioPublicKey(host)
		// if pkErr != nil {
		// 	return nil, status.Errorf(codes.FailedPrecondition, "no public key in DNS for authority %s found: %v", host, pkErr)
		// }

		// // convert to proto message
		// msg := req.(proto.Message)
		// msgDescriptor := msg.ProtoReflect().Descriptor()
		// name := msgDescriptor.Name()

		// buf, err := proto.Marshal(msg)
		// if err != nil {
		// 	return nil, status.Error(codes.Internal, "failed to marshal request message")
		// }

		// // extract essential payloads
		// var payload []byte
		// var cborPayload []byte
		// var signature []byte

		// if name == "HandshakeSignedRequest" {
		// 	var handshake v1.HandshakeSignedRequest
		// 	err := proto.Unmarshal(buf, &handshake)
		// 	if err != nil {
		// 		return nil, status.Error(codes.Internal, "failed to unmarshal HandshakeSignedRequest")
		// 	}
		// 	cborPayload = handshake.GetCborPayload()
		// 	signature = handshake.GetSignature()
		// 	cb, err := models.HandshakeRequestProtoToStruct(handshake.Request)
		// 	if err != nil {
		// 		return nil, status.Error(codes.Internal, "failed to convert request proto message to map message in HandshakeSignedRequest")
		// 	}
		// 	cbBytes, cbErr := crypto.NewMailioCrypto().CborEncode(cb)
		// 	if cbErr != nil {
		// 		return nil, status.Error(codes.Internal, "failed to cbor encode HandshakeSignedRequest")
		// 	}
		// 	payload = cbBytes
		// } else if name == "PongRequest" {
		// 	var pong v1.PongRequest
		// 	err := proto.Unmarshal(buf, &pong)
		// 	if err != nil {
		// 		return nil, status.Error(codes.Internal, "failed to unmarshal PongRequest")
		// 	}
		// 	// payload := pong.GetCborPayload()
		// 	// signature := pong.GetSignature()
		// 	// if !sigValidator.Validate(signature, payload) {
		// 	// 	return nil, status.Error(codes.Unauthenticated, "signature validation failed")
		// 	// }
		// } else {
		// 	return nil, status.Error(codes.Unimplemented, "Unkown request type")
		// }
		// if len(payload) < 2 || !bytes.Equal(cborPayload, payload) {
		// 	return nil, status.Error(codes.InvalidArgument, "signature validation failed")
		// }
		// if !sigValidator.Validate(signature, payload, pk) {
		// 	return nil, status.Error(codes.Unauthenticated, "signature validation failed")
		// }
		return handler(ctx, req)
	}
}
