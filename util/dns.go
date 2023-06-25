package util

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	discovery "github.com/mailio/go-mailio-core/discovery/dns"
	err "github.com/mailio/go-mailio-core/errors"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
)

var (
	// LRU Cache for storing server public keys based on the request domain
	// {key:value} = {domain:public key}
	l *lru.Cache[string, string]
	// discovery
	dnsDiscovery = discovery.NewDiscoverer()
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
		if rErr == err.ErrNotFound {
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

func GetDNSMailioPublicKey(domain string) (string, error) {
	var pk string
	if publicKey, ok := l.Get(domain); !ok {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		discovery, err := dnsDiscovery.Discover(ctx, domain)
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
