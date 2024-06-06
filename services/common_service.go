package services

import (
	"context"
	"net"
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

// // checking the database/redis cache for the specific domain
// func resolveDomain(domainRepo repository.Repository, domain string, forceDiscovery bool) (*types.Domain, error) {
// 	// get domain from database
// 	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
// 	defer cancel()

// 	// check local database
// 	response, err := domainRepo.GetByID(ctx, domain)
// 	if err != nil {
// 		if err != types.ErrNotFound {
// 			// not found in the database
// 			return nil, err
// 		}
// 	}
// 	var domainObj types.Domain
// 	// if something found, check if it's too old
// 	if response != nil && !forceDiscovery {
// 		// domain found in database
// 		mErr := repository.MapToObject(response, &domainObj)
// 		if mErr != nil {
// 			return nil, mErr
// 		}

// 		needsSaving := updateDomainIfNeeded(&domainObj, domain)
// 		if needsSaving {
// 			saveDomain(ctx, domainRepo, domain, &domainObj)
// 		}
// 		return &domainObj, nil

// 		needsSaving := false
// 		// check if domain out of date for MX
// 		ageInMillis := time.Now().UnixMilli() - domainObj.Timestamp
// 		if domainObj.SupportsStandardEmails && ageInMillis >= AGE_OF_NON_MAILIO_DOMAINS_BEFORE_REFRESH {
// 			isMx, _ := util.CheckMXRecords(domain)
// 			domainObj.SupportsStandardEmails = isMx
// 			needsSaving = true
// 		}
// 		// check if domain out of date for Mailio
// 		if ageInMillis >= AGE_OF_MAILIO_DOMAINS_BEFORE_REFRESH {
// 			// check if mailio server
// 			discovery, disErr := checkIfMailioServer(domain)
// 			if disErr != nil {
// 				if disErr != types.ErrNotFound {
// 					return nil, disErr
// 				}
// 				domainObj.SupportsMailio = false
// 			} else {
// 				domainObj.SupportsMailio = discovery.IsMailio
// 				domainObj.MailioPublicKey = discovery.PublicKey
// 				domainObj.MailioDIDDomain = discovery.MailioDIDDomain
// 			}
// 			needsSaving = true
// 		}
// 		if needsSaving {
// 			domainObj.Timestamp = time.Now().UnixMilli()
// 			sErr := domainRepo.Save(ctx, domain, &domainObj)
// 			if sErr != nil {
// 				// ignore error (we'll get it next time)
// 				level.Error(global.Logger).Log("msg", "error while saving domain", "err", sErr)
// 			}
// 		}
// 		return &domainObj, nil
// 	}

// 	newDomainObj := &types.Domain{
// 		Name:      domain,
// 		Timestamp: time.Now().UnixMilli(),
// 	}

// 	isMx, _ := util.CheckMXRecords(domain)
// 	if isMx {
// 		newDomainObj.SupportsStandardEmails = true
// 	}
// 	discovery, disErr := checkIfMailioServer(domain)
// 	if disErr != nil {
// 		if disErr != types.ErrNotFound {
// 			return nil, disErr
// 		}
// 		newDomainObj.SupportsMailio = false
// 	} else {
// 		newDomainObj.SupportsMailio = discovery.IsMailio
// 		newDomainObj.MailioPublicKey = discovery.PublicKey
// 		newDomainObj.MailioDIDDomain = discovery.MailioDIDDomain
// 	}

// 	if domainObj.ID != "" {
// 		newDomainObj.Rev = domainObj.Rev
// 	}
// 	// save to domains
// 	newDomainObj.Timestamp = time.Now().UnixMilli()

// 	sErr := domainRepo.Save(ctx, domain, newDomainObj)
// 	if sErr != nil {
// 		// ignore error (we'll get it next time)
// 		level.Error(global.Logger).Log("msg", "error while saving domain", "err", sErr)
// 	}

// 	return newDomainObj, nil
// }

// func checkIfMailioServer(domain string) (*types.Discovery, error) {
// 	allDomains := []string{domain}
// 	for _, subdomain := range global.Conf.Mailio.ServerSubdomainQueryList {
// 		allDomains = append(allDomains, subdomain.Prefix+"."+domain)
// 	}
// 	for i, possibleDomain := range allDomains {
// 		host := possibleDomain
// 		// schema added so that it can be parsed
// 		if !strings.Contains(possibleDomain, "http") {
// 			host = "http://" + host
// 		}
// 		parsedHost, pErr := url.Parse(host)
// 		if pErr != nil {
// 			global.Logger.Log(pErr.Error(), "error while parsing host")
// 			return nil, pErr
// 		}
// 		// in case of ports attached to host
// 		idnaLookupHost := parsedHost.Host
// 		if strings.Contains(idnaLookupHost, ":") {
// 			idnaLookupHost = strings.Split(idnaLookupHost, ":")[0]
// 		}
// 		lookupHost, lErr := idna.Lookup.ToASCII(idnaLookupHost)
// 		if lErr != nil {
// 			global.Logger.Log(lErr.Error(), "error converting host to IDNA")
// 			return nil, lErr
// 		}
// 		dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 3*time.Second)
// 		defer dnsCancel()

// 		discovery, dErr := util.MailioDNSDiscover(dnsCtx, lookupHost)
// 		if dErr != nil {
// 			if dErr == types.ErrNotFound && i < len(allDomains)-1 {
// 				continue
// 			}
// 			return nil, dErr
// 		}
// 		discovery.MailioDIDDomain = possibleDomain
// 		return discovery, nil
// 	}
// 	return nil, types.ErrNotFound
// }

func resolveDomain(domainRepo repository.Repository, domain string, forceDiscovery bool) (*types.Domain, error) {
	// get domain from database
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// check local database
	response, err := domainRepo.GetByID(ctx, domain)
	if err != nil && err != types.ErrNotFound {
		return nil, err
	}

	var domainObj types.Domain
	if response != nil && !forceDiscovery {
		// domain found in database
		if err := repository.MapToObject(response, &domainObj); err != nil {
			return nil, err
		}

		shouldSave := false
		ageInMillis := time.Now().UTC().UnixMilli() - domainObj.Timestamp
		if shouldUpdateStandardEmails(ageInMillis) {
			isMx, _ := util.CheckMXRecords(domain)
			domainObj.SupportsStandardEmails = isMx
			shouldSave = true
		}
		if shouldUpdateMailio(ageInMillis) {
			discovery, disErr := checkIfMailioServer(domain)
			if disErr != nil {
				if disErr != types.ErrNotFound {
					return nil, disErr
				}
				domainObj.SupportsMailio = false
			} else {
				updateMailioInfo(&domainObj, discovery)
			}
			shouldSave = true
		}
		if shouldSave {
			domainObj.Timestamp = time.Now().UTC().UnixMilli()
			saveDomain(ctx, domainRepo, domain, &domainObj)
		}
		return &domainObj, nil
	}

	// domain not found or force discovery
	newDomainObj := &types.Domain{
		Name:                   domain,
		SupportsMailio:         false,
		SupportsStandardEmails: false,
		Timestamp:              time.Now().UnixMilli(),
	}
	uErr := updateDomain(newDomainObj, domain)
	if uErr != nil {
		global.Logger.Log("msg", "error while updating domain", "err", uErr)
		return nil, uErr
	}
	saveDomain(ctx, domainRepo, domain, newDomainObj)

	return newDomainObj, nil
}

func shouldUpdateStandardEmails(ageInMillis int64) bool {
	return ageInMillis >= AGE_OF_NON_MAILIO_DOMAINS_BEFORE_REFRESH
}

func shouldUpdateMailio(ageInMillis int64) bool {
	return ageInMillis >= AGE_OF_MAILIO_DOMAINS_BEFORE_REFRESH
}

func updateMailioInfo(domainObj *types.Domain, discovery *types.Discovery) {
	domainObj.SupportsMailio = discovery.IsMailio
	domainObj.MailioPublicKey = discovery.PublicKey
	domainObj.MailioDIDDomain = discovery.MailioDIDDomain
}

func updateDomain(domainObj *types.Domain, domain string) error {
	supportsStandard, cErr := util.CheckMXRecords(domain)
	if cErr != nil {
		global.Logger.Log("msg", "error while checking MX records", "err", cErr)
		return cErr
	}
	domainObj.SupportsStandardEmails = supportsStandard
	discovery, err := checkIfMailioServer(domain)
	if err != nil {
		if err != types.ErrNotFound {
			return err
		}
		domainObj.SupportsMailio = false
		return nil
	}
	updateMailioInfo(domainObj, discovery)
	return nil
}

func saveDomain(ctx context.Context, domainRepo repository.Repository, domain string, domainObj *types.Domain) {
	if err := domainRepo.Save(ctx, domain, domainObj); err != nil {
		level.Error(global.Logger).Log("msg", "error while saving domain", "err", err)
	}
}

func checkIfMailioServer(domain string) (*types.Discovery, error) {
	allDomains := getAllPossibleDomains(domain)
	for _, possibleDomain := range allDomains {
		discovery, err := tryDiscoverMailio(possibleDomain)
		if err != nil {
			if err == types.ErrNotFound {
				continue
			}
			return nil, err
		}
		return discovery, nil
	}
	return nil, types.ErrNotFound
}

func getAllPossibleDomains(domain string) []string {
	allDomains := []string{domain}
	for _, subdomain := range global.Conf.Mailio.ServerSubdomainQueryList {
		allDomains = append(allDomains, subdomain.Prefix+"."+domain)
	}
	return allDomains
}

func tryDiscoverMailio(domain string) (*types.Discovery, error) {
	host := formatHost(domain)
	lookupHost, err := idna.Lookup.ToASCII(getHostWithoutPort(host))
	if err != nil {
		global.Logger.Log(err.Error(), "error converting host to IDNA")
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	discovery, err := util.MailioDNSDiscover(ctx, lookupHost)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok {
			if dnsErr.IsNotFound {
				return nil, types.ErrNotFound
			}
		}
		return nil, err
	}
	discovery.MailioDIDDomain = domain
	return discovery, nil
}

func formatHost(domain string) string {
	if !strings.Contains(domain, "http") {
		return "http://" + domain
	}
	return domain
}

func getHostWithoutPort(host string) string {
	parsedHost, err := url.Parse(host)
	if err != nil {
		global.Logger.Log(err.Error(), "error while parsing host")
		return host
	}

	idnaLookupHost := parsedHost.Host
	if strings.Contains(idnaLookupHost, ":") {
		idnaLookupHost = strings.Split(idnaLookupHost, ":")[0]
	}
	return idnaLookupHost
}
