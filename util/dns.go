package util

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
)

// DNS discovery of the domain.
// Returns Discovery object with the following fields:
// - Domain: domain name
// - IsMailio: true if the domain supports Mailio exchange protocol
// - PublicKeyType: type of the public key (currently only ed25519 is supported)
// - PublicKey: base64 encoded public key
// - Ips: IP addresses of the domain
func MailioDNSDiscover(ctx context.Context, domain string) (*types.Discovery, error) {
	var r net.Resolver

	if strings.Contains(domain, "localhost") {
		// if development server take the local public key

		pk := base64.StdEncoding.EncodeToString(global.PublicKey)
		if strings.Contains(domain, "localhost") {
			return &types.Discovery{
				Domain:        "localhost",
				IsMailio:      true,
				Ips:           []string{"127.0.0.1"},
				PublicKeyType: "ed25519",
				PublicKey:     pk,
			}, nil
		}

	}

	txts, err := r.LookupTXT(ctx, "mailio._mailiokey."+domain)
	if err != nil {
		return nil, err
	}
	if len(txts) == 0 {
		return nil, types.ErrNotFound
	}
	ips, _ := r.LookupIPAddr(ctx, domain)
	// read IP address
	ipAddresses := []string{}

	for _, ip := range ips {
		if ipv4 := ip.IP.To4(); ipv4 != nil {
			ipAddress := ipv4.String()
			ipAddresses = append(ipAddresses, ipAddress)
		}
	}

	// parse TXT record
	for _, txt := range txts {
		if strings.Contains(txt, "v=MAILIO1") {

			disc, err := MailioDNSParseTxtV1(txt)
			if err != nil {
				return nil, err
			}
			pkErr := validatePublicKeyLength(disc.PublicKey)
			if pkErr != nil {
				return nil, types.ErrInvalidPublicKey
			}
			disc.Domain = domain
			disc.Ips = ipAddresses
			return disc, nil
		}
	}
	return nil, types.ErrNotFound
}

// helper parsing function for MAILIO1 (version 1)
func MailioDNSParseTxtV1(txt string) (*types.Discovery, error) {
	split := strings.Split(txt, ";")
	if len(split) < 3 {
		return nil, types.ErrInvalidFormat
	}
	keyType := strings.Trim(split[1], " ")
	publicKey := strings.Trim(split[2], " ")

	if !strings.HasPrefix(keyType, "k=") {
		return nil, types.ErrInvalidFormat
	}
	if !strings.HasPrefix(publicKey, "p=") {
		return nil, types.ErrInvalidFormat
	}

	return &types.Discovery{
		IsMailio:      true,
		PublicKeyType: strings.Replace(keyType, "k=", "", 1),
		PublicKey:     strings.Replace(publicKey, "p=", "", 1),
	}, nil
}

// simple verification of the public key (only checks the length).
func validatePublicKeyLength(publicKey string) error {
	pbBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return types.ErrInvalidFormat
	}
	if len(pbBytes) != 32 {
		return types.ErrInvalidPublicKey
	}
	return nil
}

func GenerateTXTRecord(domain string, publicKeyBase64 string) (*string, error) {

	decoded, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return nil, err
	}
	if len(decoded) != 32 {
		return nil, types.ErrInvalidPublicKey
	}

	txt := "v=MAILIO1; k=ed25519; p=" + publicKeyBase64
	txtRecord := fmt.Sprintf("\"%s\"", txt)

	txtRR := fmt.Sprintf("mailio._mailiokey.%s.\tIN\tTXT\t%s", domain, txtRecord)
	return &txtRR, nil
}
