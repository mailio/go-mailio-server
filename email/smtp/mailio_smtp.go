package mailiosmtp

import (
	"sort"
	"sync"

	"github.com/mailio/go-mailio-server/email/smtp/handler"
)

var (
	handlersMu sync.RWMutex
	handlers   = make(map[string]handler.SmtpHandler)
)

// RegisterSmtpHandler makes a smtp handler available by the provided name.
// If RegisterSmtpHandler is called twice with the same name or if driver is nil,
// it panics.
func RegisterSmtpHandler(name string, h handler.SmtpHandler) {
	handlersMu.Lock()
	defer handlersMu.Unlock()
	if h == nil {
		panic("smtp: Register handler is nil")
	}
	if _, dup := handlers[name]; dup {
		panic("smtp: Register called twice for handler " + name)
	}
	handlers[name] = h
}

func unregisterAllHandlers() {
	handlersMu.Lock()
	defer handlersMu.Unlock()
	// For tests.
	handlers = make(map[string]handler.SmtpHandler)
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
