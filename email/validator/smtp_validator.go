package validator

import (
	"sort"
	"sync"

	mailiosmtp "github.com/mailio/go-mailio-server/email/smtp/types"
)

var (
	handlersMu sync.RWMutex
	handlers   = make(map[string]SmtpValidator)
)

type SmtpValidator interface {
	Validate(*mailiosmtp.Mail) error
}

// RegisterSmtpValidatorHandler makes a smtp handler available by the provided name.
// If RegisterSmtpValidatorHandler is called twice with the same name or if driver is nil,
// it panics.
func RegisterSmtpValidatorHandler(name string, h SmtpValidator) {
	handlersMu.Lock()
	defer handlersMu.Unlock()
	if h == nil {
		panic("smtp: Register smtp validation handler is nil")
	}
	if _, dup := handlers[name]; dup {
		panic("smtp: Register smtp validation called twice for handler " + name)
	}
	handlers[name] = h
}

// for tests only
func unregisterAllHandlers() {
	handlersMu.Lock()
	defer handlersMu.Unlock()
	// For tests.
	handlers = make(map[string]SmtpValidator)
}

// Drivers returns a sorted list of the names of the registered drivers.
func Handlers() []string {
	handlersMu.RLock()
	defer handlersMu.RUnlock()
	list := make([]string, 0, len(handlers))
	for name := range handlers {
		list = append(list, name)
	}
	sort.Strings(list)
	return list
}

func GetHandler(name string) SmtpValidator {
	handlersMu.RLock()
	defer handlersMu.RUnlock()
	if h, ok := handlers[name]; ok {
		return h
	}
	return nil
}
