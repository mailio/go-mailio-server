package services

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
)

/**
 * GetByID returns a handshake by ID of a specific mailio user from local database
 */
func GetHandshakeByID(userRepo repository.Repository, handshakeOwnerAddress string, handshakeID string) (*types.StoredHandshake, error) {
	hexUser := "userdb-" + hex.EncodeToString([]byte(handshakeOwnerAddress))

	url := fmt.Sprintf("%s/%s", hexUser, handshakeID)

	var storedHandshake types.StoredHandshake
	resp, err := userRepo.GetClient().(*resty.Client).R().SetResult(&storedHandshake).Get(url)
	if err != nil {
		global.Logger.Log("HandshakeService.GetByID", "failed to get", err.Error())
		return nil, err
	}
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		return nil, fmt.Errorf("failed to get handshake by ID")
	}

	return &storedHandshake, nil
}

func GetHandshakeByMailioAddress(userRepo repository.Repository, handshakeOwnerAddress string, senderAddress string) (*types.StoredHandshake, error) {
	handshakeIDConcat := handshakeOwnerAddress + senderAddress
	s256 := sha256.Sum256([]byte(handshakeIDConcat))
	handshakeID := hex.EncodeToString(s256[:])

	return GetHandshakeByID(userRepo, handshakeOwnerAddress, handshakeID)
}
