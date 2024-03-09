package util

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/mailio/go-mailio-server/types"
)

// converts the DID document to unique ID
func DIDDocumentToUniqueID(message *types.DIDCommMessage, optionalSuffix string) (string, error) {
	if message == nil {
		return "", types.ErrBadRequest
	}
	if message.CreatedTime == 0 {
		return "", types.ErrBadRequest
	}
	m, mErr := json.Marshal(message)
	if mErr != nil {
		return "", mErr
	}
	m = append(m, []byte(fmt.Sprintf("%d", time.Now().UTC().UnixMilli()))...)
	if optionalSuffix != "" {
		m = append(m, []byte(optionalSuffix)...)
	}
	hex := Sha256Hex(m)
	return hex, nil
}
