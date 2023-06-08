package apigrpc

import (
	"github.com/mailio/go-mailio-core/crypto"
	"github.com/mailio/go-mailio-server/apigrpc/interceptors"
)

// GrpcSignatureValidator is a struct that implements SignatureValidator interface
type GrpcSignatureValidator struct {
	sv interceptors.SignatureValidator
	mc crypto.MailioCrypto
}

func NewGrpcSignatureValidator() *GrpcSignatureValidator {
	return &GrpcSignatureValidator{
		mc: crypto.NewMailioCrypto(),
	}
}

// Validate digital signature implementation fo SignatureValidator interface main method (Validate)
func (gsv *GrpcSignatureValidator) Validate(signature, payload []byte, publicKeyBase64 string) bool {
	v, err := gsv.mc.Verify(payload, signature, publicKeyBase64)
	return v && err == nil
}
