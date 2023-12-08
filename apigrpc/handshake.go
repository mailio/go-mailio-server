package apigrpc

// import (
// 	"context"
// 	"encoding/base64"
// 	"time"

// 	"github.com/mailio/go-mailio-core/crypto"
// 	v1 "github.com/mailio/go-mailio-core/proto/gen"
// 	"github.com/mailio/go-mailio-server/global"
// 	"github.com/mailio/go-mailio-server/services"
// 	"github.com/mailio/go-mailio-server/types"
// 	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
// )

// type GrpcHandshake struct {
// 	v1.UnimplementedHandshakeServiceServer
// 	handshakeService *services.HandshakeService
// 	environment      *types.Environment
// }

// func NewGrpcHandshake(handshakeService *services.HandshakeService, env *types.Environment) *GrpcHandshake {
// 	return &GrpcHandshake{
// 		handshakeService: handshakeService,
// 		environment:      env,
// 	}
// }

// // checkNotFoundError handles a case where not found error is returned
// func checkNotFoundError(f *types.Handshake, err error) (*types.Handshake, error) {
// 	if err != nil {
// 		if err == types.ErrNotFound {
// 			return nil, nil
// 		}
// 		return nil, err
// 	}
// 	return f, nil
// }

// func (hs *GrpcHandshake) Handshake(ctx context.Context, req *v1.HandshakeSignedRequest) (*v1.HandshakeSignedResponse, error) {
// 	//TODO: if the handshake is not found in couchdb then we return a default server handshake
// 	request := req.GetRequest()
// 	lookups := request.GetLookup()

// 	signedResponse := &v1.HandshakeSignedResponse{
// 		Content: []*v1.HandshakeContent{},
// 	}

// 	senderAddress := request.GetSenderAddress()

// 	for _, lookup := range lookups {
// 		var found *types.Handshake

// 		if lookup.GetAddress() != "" {
// 			f, err := hs.handshakeService.LookupHandshake(lookup.GetAddress(), senderAddress)
// 			found, err = checkNotFoundError(f, err)
// 		}
// 		if lookup.GetScryptLookupEmail() != "" {
// 			// TODO: this is not right, we need to lookup the email in the db
// 			f, err := hs.handshakeService.LookupHandshake(lookup.GetScryptLookupEmail(), senderAddress)
// 			found, err = checkNotFoundError(f, err)
// 		}
// 		if lookup.GetHandshakeId() != "" {
// 			f, err := hs.handshakeService.GetByID(lookup.GetHandshakeId())
// 			found, err = checkNotFoundError(f, err)
// 		}
// 		if found != nil {
// 			fc := found.Content
// 			created := time.Unix(fc.Created/1000, fc.Created%1000*1000000)
// 			ownerPublicKey, dErr := base64.StdEncoding.DecodeString(fc.OwnerPublicKeyBase64)
// 			if dErr != nil {
// 				return nil, dErr
// 			}
// 			content := &v1.HandshakeContent{
// 				HandshakeId:     fc.HandshakeID,
// 				OwnerAddressHex: fc.OwnerAddressHex,
// 				SenderAddress:   fc.SenderAddress,
// 				SignatureScheme: v1.SigScheme_EdDSA_X25519,
// 				Type:            v1.HandshakeType(fc.Type),
// 				OriginServer: &v1.HandshakeOriginServer{
// 					Domain: global.Conf.Mailio.Domain,
// 				},
// 				Status:            v1.HandshakeStatus(fc.Status),
// 				ScryptLookupEmail: lookup.GetScryptLookupEmail(), // requested scrypt email
// 				Created:           timestamppb.New(created),
// 				OwnerPublicKey:    ownerPublicKey,
// 				Level:             v1.MinimumHandshakeLevel(fc.Level),
// 			}
// 			if fc.SignupSubType != nil {
// 				st := *fc.SignupSubType
// 				content.Subtype = v1.HandshakeSignupSubType(st).Enum()
// 			} else {
// 				content.Subtype = v1.HandshakeSignupSubType_OTHER.Enum()
// 			}
// 			if fc.SignupRules != nil {
// 				rules := *fc.SignupRules
// 				content.Rules = &v1.HandshakeSignupRules{
// 					FrequencyMinutes: int32(rules.FrequencyMinutes),
// 				}
// 			}

// 			signedResponse.Content = append(signedResponse.Content, content)
// 		}
// 	}

// 	// server side signature authenticating the response
// 	cbBytes, cbErr := hs.environment.MailioCrypto.CborEncode(signedResponse.Content)
// 	if cbErr != nil {
// 		global.Logger.Log("msg", "failed to encode response", "err", cbErr)
// 		return nil, cbErr
// 	}

// 	signature, sigErr := crypto.NewMailioCrypto().Sign(cbBytes, base64.StdEncoding.EncodeToString(global.PrivateKey))
// 	if sigErr != nil {
// 		return nil, sigErr
// 	}
// 	signedResponse.CborPayload = cbBytes
// 	signedResponse.Signature = signature

// 	return signedResponse, nil
// }
