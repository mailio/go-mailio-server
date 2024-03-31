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
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type HandshakeService struct {
	handshakeRepo repository.Repository
	userRepo      repository.Repository
}

func NewHandshakeService(dbSelector repository.DBSelector) *HandshakeService {
	handshakeRepo, err := dbSelector.ChooseDB(repository.Handshake)
	if err != nil {
		level.Error(global.Logger).Log("msg", "error while choosing db", "err", err)
		panic(err)
	}
	userRepo, err := dbSelector.ChooseDB(repository.User)
	if err != nil {
		level.Error(global.Logger).Log("msg", "error while choosing db", "err", err)
		panic(err)
	}
	return &HandshakeService{handshakeRepo: handshakeRepo, userRepo: userRepo}
}

// Save a handshake into a database
func (hs *HandshakeService) Save(handshake *types.Handshake, userPublicKeyEd25519Base64 string) error {
	// basic sanity check
	if handshake == nil || handshake.Content.HandshakeID == "" {
		return types.ErrBadRequest
	}
	if handshake.Content.SenderMetadata == nil {
		return types.ErrBadRequest
	}
	if handshake.Content.Type < types.HANDSHAKE_TYPE_PERSONAL || handshake.Content.Type > types.HANDSHAKE_TYPE_USER_SPECIFIC {
		return types.ErrBadRequest
	}

	pubKeyFromBase, pkErr := base64.StdEncoding.DecodeString(userPublicKeyEd25519Base64)
	ownerMailioAddr, mErr := util.PublicKeyToMailioAddress(pubKeyFromBase)
	if errors.Join(mErr, pkErr) != nil {
		return errors.Join(mErr, pkErr)
	}
	if ownerMailioAddr != handshake.Content.OwnerAddressHex {
		return errors.New("owner address does not match")
	}
	senderAddress := ""
	if handshake.Content.SenderMetadata != nil {
		if handshake.Content.SenderMetadata.Address != "" {
			senderAddress = handshake.Content.SenderMetadata.Address // mailio address
		} else {
			senderAddress = handshake.Content.SenderMetadata.EmailHash // script
		}
	}
	handshakeIDConcat := ownerMailioAddr + senderAddress
	s256 := sha256.Sum256([]byte(handshakeIDConcat))
	handshakeID := hex.EncodeToString(s256[:])
	handshake.Content.HandshakeID = handshakeID

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// verify handshakes digital signature
	isValid, vErr := util.VerifyHandshake(handshake, userPublicKeyEd25519Base64)
	if vErr != nil {
		global.Logger.Log(vErr.Error(), "failed to verify handshake", "owner", ownerMailioAddr, "sender", senderAddress)
		return types.ErrSignatureInvalid
	}

	if !isValid {
		return types.ErrSignatureInvalid
	}

	// check if handshake already exists (overide if it does)
	existingHs, eErr := GetByID(hs.handshakeRepo, handshake.Content.HandshakeID)
	if eErr != nil {
		if eErr != types.ErrNotFound {
			return eErr
		}
	}
	// convert models.Handshake to types.StoredHandshale
	storedHandshake := types.StoredHandshake{
		Content:           handshake.Content,
		OwnerAddress:      ownerMailioAddr,
		SignatureBase64:   handshake.SignatureBase64,
		CborPayloadBase64: handshake.CborPayloadBase64,
		Timestamp:         time.Now().UTC().UnixMilli(),
	}
	if existingHs != nil {
		storedHandshake.Rev = existingHs.Rev
	}

	return hs.handshakeRepo.Save(ctx, handshake.Content.HandshakeID, storedHandshake)
}

// List all handshakes by specific address
func (hs *HandshakeService) ListHandshakes(address string, bookmark string, limit int) (*types.PagingResults, error) {

	var couchdbError types.CouchDBError

	cl := hs.handshakeRepo.GetClient().(*resty.Client)
	query := map[string]interface{}{
		"selector": map[string]interface{}{
			"ownerAddress": address,
		},
		"use_index": []string{"ownerAddress-index"},
		"limit":     limit,
		"sort":      []map[string]string{{"timestamp": "desc"}},
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
	if docs, ok := respObj["docs"]; ok {
		handshakes = docs.([]interface{})
	}
	results := &types.PagingResults{
		Docs: handshakes,
	}
	if bm, ok := respObj["bookmark"]; ok {
		if bm != nil && bm.(string) != "nil" {
			results.Bookmark = bm.(string)
		}
	}

	return results, nil
}

// return handshake by ID from database
func (hs *HandshakeService) GetByID(handshakeID string) (*types.StoredHandshake, error) {
	return GetByID(hs.handshakeRepo, handshakeID)
}

// return handshake by mailio address (where ownerAddress is current users Mailio address and senderAddress is scrypt address or Mailio address)
func (hs *HandshakeService) GetByMailioAddress(ownerAddress string, senderAddress string) (*types.StoredHandshake, error) {
	return GetByMailioAddress(hs.handshakeRepo, ownerAddress, senderAddress)
}
