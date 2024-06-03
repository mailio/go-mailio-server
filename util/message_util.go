package util

import (
	"encoding/json"
	"fmt"
	"time"

	smtptypes "github.com/mailio/go-mailio-server/email/smtp/types"
	"github.com/mailio/go-mailio-server/global"
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

func SmtpMailToUniqueID(email *smtptypes.Mail, optionalSuffix string) (string, error) {
	if email == nil {
		return "", types.ErrBadRequest
	}
	if email.Timestamp == 0 {
		return "", types.ErrBadRequest
	}
	m, mErr := json.Marshal(email)
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

func ListDomains() []string {
	domains := []string{}
	for _, srv := range global.Conf.SmtpServers {
		for _, domain := range srv.Domains {
			domains = append(domains, domain.Domain)
		}
	}
	return domains
}

// IsSupportedDomain checks if the domain is in the list of smtp server domains or mailio domains
func IsSupportedDomain(domain string) bool {
	for _, d := range ListDomains() {
		if d == domain {
			return true
		}
	}
	return false
}
