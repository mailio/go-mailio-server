package services

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/go-kit/log/level"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
	"golang.org/x/net/idna"
)

const (
	AGE_OF_NON_MAILIO_DOMAINS_BEFORE_REFRESH = 24 * 60 * 60 * 60 * 1000 // 60 days
	AGE_OF_MAILIO_DOMAINS_BEFORE_REFRESH     = 24 * 60 * 60 * 1000      // 1 day
)

func getUserByScryptEmail(repo repository.Repository, hashedEmail string) (*types.EmailToMailioMapping, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	response, eErr := repo.GetByID(ctx, hashedEmail)
	if eErr != nil {
		return nil, eErr
	}
	var userMapping types.EmailToMailioMapping
	mErr := repository.MapToObject(response, &userMapping)
	if mErr != nil {
		return nil, mErr
	}
	return &userMapping, nil
}

// checking the database/redis cache for the specific domain
func resolveDomain(domainRepo repository.Repository, domain string, forceDiscovery bool) (*types.Domain, error) {
	// get domain from database
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	host := domain
	if !strings.Contains(domain, "http") {
		host = "http://" + host
	}
	parsedHost, pErr := url.Parse(host)
	if pErr != nil {
		global.Logger.Log(pErr.Error(), "error while parsing host")
		return nil, pErr
	}
	lookupHost, lErr := idna.Lookup.ToASCII(parsedHost.Host)
	if lErr != nil {
		global.Logger.Log(lErr.Error(), "error converting host to IDNA")
		return nil, lErr
	}

	var domainObj *types.Domain

	if !forceDiscovery { // check local database

		response, err := domainRepo.GetByID(ctx, lookupHost)
		if err != nil {
			if err != types.ErrNotFound {
				// not found in the database
				return nil, err
			}
		} else {
			// domain found in database
			mErr := repository.MapToObject(response, domainObj)
			if mErr != nil {
				return nil, mErr
			}
			ageInMillis := time.Now().UnixMilli() - domainObj.Timestamp
			if !domainObj.IsMailioServer && ageInMillis < AGE_OF_NON_MAILIO_DOMAINS_BEFORE_REFRESH {
				return domainObj, nil
			}
			if ageInMillis < AGE_OF_MAILIO_DOMAINS_BEFORE_REFRESH {
				// return only if the domain record is not older than AGE_OF_MAILIO_DOMAINS_BEFORE_REFRESH
				return domainObj, nil
			}
		}
	}
	// request DNS for the domain mailio domains public key
	dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dnsCancel()
	discovery, dErr := util.MailioDNSDiscover(dnsCtx, lookupHost)
	if dErr != nil {
		return nil, dErr
	}
	updatedDomainObj := &types.Domain{
		Name:            discovery.Domain,
		IsMailioServer:  discovery.IsMailio,
		MailioPublicKey: discovery.PublicKey,
		Timestamp:       time.Now().UnixMilli(),
	}
	if domainObj != nil {
		updatedDomainObj.Rev = domainObj.Rev
	}
	// save to domains
	sErr := domainRepo.Save(ctx, domain, domainObj)
	if sErr != nil {
		// ignore error (we'll get it next time)
		level.Error(global.Logger).Log("msg", "error while saving domain", "err", sErr)
	}

	return domainObj, nil
}
