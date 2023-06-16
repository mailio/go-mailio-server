package util

import (
	"encoding/hex"
	"errors"

	"github.com/mailio/go-mailio-server/global"
	"golang.org/x/crypto/scrypt"
)

var (
	scryptN   = 32768 // N = CPU/memory cost parameter (suitable as of 2017)
	scryptR   = 8     // r and p must satisfy r * p < 2^30
	scryptP   = 1
	scryptLen = 32 // 32 bytes long
)

func ScryptEmail(email string) ([]byte, error) {
	slt := global.Conf.Mailio.EmailSaltHex
	if slt == "" {
		return nil, errors.New("emailSalt configuration is empty")
	}
	emailSalt, dErr := hex.DecodeString(slt)
	if dErr != nil {
		return nil, dErr
	}

	dk, err := scrypt.Key([]byte(email), emailSalt, scryptN, scryptR, scryptP, scryptLen)
	if err != nil {
		return nil, err
	}
	return dk, nil
}
