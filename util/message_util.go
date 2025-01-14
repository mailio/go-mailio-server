package util

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
	"golang.org/x/net/publicsuffix"
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

func SmtpMailToUniqueID(email *types.SmtpEmailInput, optionalSuffix string) (string, error) {
	if email == nil {
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

func ListSmtpDomains() []string {
	domains := []string{}
	for _, srv := range global.Conf.SmtpServers {
		for _, domain := range srv.Domains {
			domains = append(domains, domain.Domain)
		}
	}
	return domains
}

func ExtractRootDomain(domain string) (string, error) {
	// Get the root domain using the publicsuffix library
	rootDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return "", err
	}
	return rootDomain, nil
}

// IsSupportedDomain checks if the domain is in the list of smtp server domains or mailio domains
func IsSupportedSmtpDomain(domain string) bool {
	rootDomain, rdErr := ExtractRootDomain(domain)
	if rdErr != nil {
		global.Logger.Log(rdErr, "failed to extract root domain")
		return false
	}

	for _, smtpDomain := range ListSmtpDomains() {
		smtpDomainRoot, smtpErr := ExtractRootDomain(smtpDomain)
		if smtpErr != nil {
			global.Logger.Log(smtpErr, "failed to extract root domain", smtpErr.Error())
			return false
		}
		if smtpDomainRoot == rootDomain {
			return true
		}
	}
	return false
}

// Extract the corresponding smtp sending domain for the given domain from the configuration
func ExtractSmtpSendingDomain(domain string) (string, error) {
	rootDomain, rdErr := ExtractRootDomain(domain)
	if rdErr != nil {
		global.Logger.Log(rdErr, "failed to extract root domain")
		return "", rdErr
	}

	for _, smtpDomain := range ListSmtpDomains() {
		smtpDomainRoot, smtpErr := ExtractRootDomain(smtpDomain)
		if smtpErr != nil {
			global.Logger.Log(smtpErr, "failed to extract root domain", smtpErr.Error())
			return "", smtpErr
		}
		if smtpDomainRoot == rootDomain {
			return smtpDomain, nil
		}
	}
	return "", types.ErrBadRequest
}
