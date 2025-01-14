package services

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
)

/**
 * GetByID returns a handshake by ID of a specific mailio user from local database
 */
func GetHandshakeByID(userRepo repository.Repository, handshakeOwnerAddress string, handshakeID string) (*types.Handshake, error) {
	hexUser := "userdb-" + hex.EncodeToString([]byte(handshakeOwnerAddress))

	url := fmt.Sprintf("%s/%s", hexUser, handshakeID)

	resp, err := userRepo.GetClient().(*resty.Client).R().Get(url)
	if err != nil {
		global.Logger.Log("HandshakeService.GetByID", "failed to get", err.Error())
		return nil, err
	}
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		if resp.StatusCode() == 404 {
			return nil, types.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get handshake by ID")
	}

	var hs types.MailioMessage
	body := resp.Body()
	mErr := json.Unmarshal(body, &hs)
	if mErr != nil {
		return nil, mErr
	}
	if hs.DIDCommMessage.PlainBodyBase64 == "" {
		return nil, types.ErrNotFound
	}
	hsBody, hsErr := base64.StdEncoding.DecodeString(hs.DIDCommMessage.PlainBodyBase64)
	if hsErr != nil {
		return nil, hsErr
	}
	var handshake types.Handshake
	hsErr = json.Unmarshal(hsBody, &handshake)
	if hsErr != nil {
		return nil, hsErr
	}

	return &handshake, nil
}

func GetHandshakeByMailioAddress(userRepo repository.Repository, handshakeOwnerAddress string, senderAddress string) (*types.Handshake, error) {
	handshakeIDConcat := handshakeOwnerAddress + senderAddress
	s256 := sha256.Sum256([]byte(handshakeIDConcat))
	handshakeID := hex.EncodeToString(s256[:])

	return GetHandshakeByID(userRepo, handshakeOwnerAddress, handshakeID)
}
