package services

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-kit/log/level"
	"github.com/go-resty/resty/v2"
	coreErrors "github.com/mailio/go-mailio-core/errors"
	"github.com/mailio/go-mailio-core/models"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
)

type HandshakeService struct {
	handshakeRepo repository.Repository
	env           *types.Environment
}

func NewHandshakeService(dbSelector repository.DBSelector, environment *types.Environment) *HandshakeService {
	handshakeRepo, err := dbSelector.ChooseDB(repository.Handshake)
	if err != nil {
		level.Error(global.Logger).Log("msg", "error while choosing db", "err", err)
		panic(err)
	}
	return &HandshakeService{handshakeRepo: handshakeRepo, env: environment}
}

// Save a handshake into a database
func (hs *HandshakeService) Save(handshake *types.Handshake, userPublicKeyEd25519Base64 string) error {
	// basic sanity check
	if handshake == nil || handshake.Content.HandshakeID == "" {
		return coreErrors.ErrBadRequest
	}
	if handshake.Content.SenderAddress == "" {
		return coreErrors.ErrBadRequest
	}

	ownerMailioAddr, mErr := hs.env.MailioCrypto.PublicKeyToMailioAddress(userPublicKeyEd25519Base64)
	if mErr != nil {
		return mErr
	}
	if *ownerMailioAddr != handshake.Content.OwnerAddressHex {
		return errors.New("owner address does not match")
	}
	handshakeIDConcat := *ownerMailioAddr + handshake.Content.SenderAddress
	s256 := sha256.Sum256([]byte(handshakeIDConcat))
	handshakeID := hex.EncodeToString(s256[:])
	handshake.Content.HandshakeID = handshakeID

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	vfHandshake := &models.Handshake{
		Content:     handshake.Content,
		Signature:   handshake.SignatureBase64,
		CborPayload: handshake.CborPayloadBase64,
	}
	isValid, vErr := hs.env.MailioCrypto.VerifyHandshake(vfHandshake, userPublicKeyEd25519Base64)
	if vErr != nil {
		return vErr
	}

	if !isValid {
		return coreErrors.ErrSignatureInvalid
	}

	// check if handshake already exists (overide if it does)
	existingHs, eErr := hs.GetByID(handshake.Content.HandshakeID)
	if eErr != nil {
		if eErr != coreErrors.ErrNotFound {
			return eErr
		}
	}
	if existingHs != nil {
		handshake.UnderscoreRev = existingHs.UnderscoreRev
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

// Lookup handshake in the local database (local meaning this servers database)
// lookup by senderAddress (either mailio address or an email address) or by handshakeID (if handshakeID is provided, senderAddress is ignored)
func (hs *HandshakeService) LookupHandshake(userOwnerMailioAddress string, senderAddress string) (*models.Handshake, error) {
	if senderAddress == "" || userOwnerMailioAddress == "" {
		return nil, coreErrors.ErrBadRequest
	}

	shake, err := hs.GetByMailioAddress(userOwnerMailioAddress, senderAddress)
	if err != nil {
		if err == coreErrors.ErrNotFound {
			// return default server handshake
			b64PublicKey := base64.StdEncoding.EncodeToString(global.PublicKey)
			b64PrivateKey := base64.StdEncoding.EncodeToString(global.PrivateKey)
			handshake, hsErr := hs.env.MailioCrypto.ServerSideHandshake(b64PublicKey, b64PrivateKey, global.Conf.Mailio.Domain, senderAddress)
			if hsErr != nil {
				level.Error(global.Logger).Log("msg", "error while creating handshake", "err", hsErr)
				return nil, hsErr
			}
			return handshake, nil
		}
		return nil, err
	}
	out := &models.Handshake{
		Content:     shake.Content,
		Signature:   shake.SignatureBase64,
		CborPayload: shake.CborPayloadBase64,
	}
	return out, nil
}

// returns default server handshake (used when there is no users handshake related to the sender)
func (hs *HandshakeService) GetServerHandshake(senderAddress string) (*models.Handshake, error) {
	handshake, hErr := hs.env.MailioCrypto.ServerSideHandshake(string(global.PublicKey), string(global.PrivateKey), global.Conf.Mailio.Domain, senderAddress)
	if hErr != nil {
		level.Error(global.Logger).Log("msg", "error while creating handshake", "err", hErr)
		return nil, hErr
	}
	return handshake, nil
}

// Get handshake by ID
func (hs *HandshakeService) GetByID(handshakeID string) (*types.Handshake, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	handshakeResponse, err := hs.handshakeRepo.GetByID(ctx, handshakeID)
	if err != nil {
		return nil, err
	}
	var handshake types.Handshake
	mErr := repository.MapToObject(handshakeResponse, &handshake)
	if mErr != nil {
		return nil, mErr
	}

	return &handshake, nil
}

// get handshake by mailio address (where ID of the handshake is constructed from userOwnerAddress and senderAddress)
// senderAddress can be either mailio address or email address
func (hs *HandshakeService) GetByMailioAddress(userOwnerAddress string, senderAddress string) (*types.Handshake, error) {

	handshakeIDConcat := userOwnerAddress + senderAddress
	s256 := sha256.Sum256([]byte(handshakeIDConcat))
	handshakeID := hex.EncodeToString(s256[:])

	handshake, err := hs.GetByID(handshakeID)
	if err != nil {
		return nil, err
	}

	return handshake, nil
}
