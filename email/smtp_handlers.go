package smtp

import (
	"sort"
	"sync"

	mailioabi "github.com/mailio/go-mailio-smtp-abi"
)

var (
	handlersMu sync.RWMutex
	handlers   = make(map[string]mailioabi.SmtpHandler)
)

// RegisterSmtpHandler makes a smtp handler available by the provided name.
// If RegisterSmtpHandler is called twice with the same name or if driver is nil,
// it panics.
func RegisterSmtpHandler(name string, h mailioabi.SmtpHandler) {
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

// for tests only
func UnregisterAllHandlers() {
	handlersMu.Lock()
	defer handlersMu.Unlock()
	// For tests.
	handlers = make(map[string]mailioabi.SmtpHandler)
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

func GetHandler(name string) mailioabi.SmtpHandler {
	handlersMu.RLock()
	defer handlersMu.RUnlock()
	if h, ok := handlers[name]; ok {
		return h
	}
	return nil
}
