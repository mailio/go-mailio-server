package services

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-kit/log/level"
	"github.com/go-resty/resty/v2"
	coreErrors "github.com/mailio/go-mailio-core/errors"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
)

type HandshakeService struct {
	handshakeRepo repository.Repository
}

func NewHandshakeService(dbSelector repository.DBSelector) *HandshakeService {
	handshakeRepo, err := dbSelector.ChooseDB(repository.Handshake)
	if err != nil {
		level.Error(global.Logger).Log("msg", "error while choosing db", "err", err)
		panic(err)
	}
	return &HandshakeService{handshakeRepo: handshakeRepo}
}

// Save a handshake into a database
func (hs *HandshakeService) Save(handshake *types.Handshake, userPublicKeyEd25519Base64 string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// Verify signature
	signature, sErr := base64.StdEncoding.DecodeString(handshake.SignatureBase64)
	if sErr != nil {
		return sErr
	}
	pk, pkErr := base64.StdEncoding.DecodeString(userPublicKeyEd25519Base64)
	if pkErr != nil {
		return pkErr
	}
	cborPayloadBytes, cbErr := base64.StdEncoding.DecodeString(handshake.CborPayloadBase64)
	if cbErr != nil {
		return cbErr
	}

	isValid := ed25519.Verify(ed25519.PublicKey(pk), cborPayloadBytes, signature)
	if !isValid {
		return coreErrors.ErrSignatureInvalid
	}

	return hs.handshakeRepo.Save(ctx, handshake.Content.HandshakeID, handshake)
}

// List all handshakes by specific address
func (hs *HandshakeService) ListHandshakes(address string, bookmark string, limit int) (*types.PagingResults, error) {

	var couchdbError types.CouchDBError

	cl := hs.handshakeRepo.GetClient().(*resty.Client)
	query := map[string]interface{}{
		"selector": map[string]interface{}{
			"ownerAddress": address,
		},
		"use_index": []string{"ownerAddressDesign", "ownerAddress-index"},
		"limit":     limit,
		"sort":      []map[string]string{{"created": "desc"}},
	}
	if bookmark != "" {
		query["bookmark"] = bookmark
	}
	response, err := cl.R().SetError(&couchdbError).SetBody(query).Post(fmt.Sprintf("%s/_find?bookmark=%s", hs.handshakeRepo.GetDBName(), bookmark))
	if err != nil {
		return nil, err
	}

	if response.IsError() {
		return nil, fmt.Errorf("error while fetching all handshakes: %s", couchdbError.Error)
	}
	var respObj map[string]interface{}
	mErr := json.Unmarshal(response.Body(), &respObj)
	if mErr != nil {
		return nil, mErr
	}

	handshakes := []interface{}{}
	if rows, ok := respObj["docs"]; ok {
		for _, row := range rows.([]interface{}) {
			r := row.(map[string]interface{})
			if value, ok := r["value"]; ok {
				handshakes = append(handshakes, value)
			}
		}
	}
	results := &types.PagingResults{
		Docs: handshakes,
	}
	if bm, ok := respObj["bookmark"]; ok {
		if bm != nil && "nil" != bm.(string) {
			results.Bookmark = bm.(string)
		}
	}

	return results, nil
}
