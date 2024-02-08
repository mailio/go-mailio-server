package util

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
)

var (
	// LRU Cache for storing server public keys based on the request domain
	// {key:value} = {domain:public key}
	l *lru.Cache[string, string]
	// discovery
	// dnsDiscovery = discovery.NewDiscoverer()
	// I/O thread-safe file
	cacheFile *SafeFile
)

func init() {
	// init domain cache file
	cf, cfErr := NewSafeFile(os.TempDir() + "/mailio_domain_cache.gob")
	if cfErr != nil {
		panic(cfErr)
	}

	lr, lrErr := lru.New[string, string](5000)
	if lrErr != nil {
		panic(lrErr)
	}

	data, rErr := cf.Read()
	if rErr != nil {
		if rErr == types.ErrNotFound {
			l = lr
		} else {
			panic(rErr)
		}
	} else {
		for _, kv := range data.Value {
			lr.Add(kv.Key, kv.Value)
		}
		l = lr
	}
	cacheFile = cf

}

func GetDNSMailioPublicKey(ctx context.Context, domain string) (string, error) {
	var pk string
	if publicKey, ok := l.Get(domain); !ok {
		discovery, err := MailioDNSDiscover(ctx, domain)
		if err != nil {
			return "", errors.New(fmt.Sprintf("no public key in DNS for authority %s found", domain))
		}
		keyType := discovery.PublicKeyType
		if keyType != "ed25519" {
			return "", errors.New(fmt.Sprintf("public key type %s not supported", keyType))
		}
		pk = discovery.PublicKey

		l.Add(domain, pk)

		// write new domain to cache file (first convert to orginary map so it's gob-serializable)
		var kvPairs []types.KeyValue
		for _, key := range l.Keys() {
			if val, ok := l.Get(key); ok {
				kvPairs = append(kvPairs, types.KeyValue{
					Key:   key,
					Value: val,
				})
			}
		}
		data := &Data{
			Value: kvPairs,
		}
		wErr := cacheFile.Write(data)
		if wErr != nil {
			global.Logger.Log(wErr)
		}
	} else {
		pk = publicKey
	}

	return pk, nil
}

// DNS discovery of the domain.
// Returns Discovery object with the following fields:
// - Domain: domain name
// - IsMailio: true if the domain supports Mailio exchange protocol
// - PublicKeyType: type of the public key (currently only ed25519 is supported)
// - PublicKey: base64 encoded public key
// - Ips: IP addresses of the domain
func MailioDNSDiscover(ctx context.Context, domain string) (*types.Discovery, error) {
	var r net.Resolver

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
	if ips != nil {
		for _, ip := range ips {
			if ipv4 := ip.IP.To4(); ipv4 != nil {
				ipAddress := ipv4.String()
				ipAddresses = append(ipAddresses, ipAddress)
			}
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
