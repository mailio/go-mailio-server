package diskusage

import (
	"sort"
	"sync"

	types "github.com/mailio/go-mailio-server/diskusage/types"
)

var (
	handlersMu sync.RWMutex
	handlers   = make(map[string]DiskUsageHandler)
)

type DiskUsageHandler interface {
	// This functionality is primarily used by a module that processes data collected by the AWS Inventory System
	// or any other inventory system. The module will collect the disk usage but will not store the information.
	// it's responsability of the implemented module to retrieve/store/handle the data any way it sees fit.
	// address - mailio address
	GetDiskUsage(address string) (*types.DiskUsage, error)
}

// RegisterCronHandler makes a smtp handler available by the provided name.
// If RegisterCronHandler is called twice with the same name or if driver is nil,
// it panics.
func RegisterDiskUsageHandler(name string, h DiskUsageHandler) {
	handlersMu.Lock()
	defer handlersMu.Unlock()
	if h == nil {
		panic("diskusage: Register handler is nil")
	}
	if _, dup := handlers[name]; dup {
		panic("diskusage: Register called twice for handler " + name)
	}
	handlers[name] = h
}

// for tests only
func unregisterAllHandlers() {
	handlersMu.Lock()
	defer handlersMu.Unlock()
	// For tests.
	handlers = make(map[string]DiskUsageHandler)
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

func GetHandler(name string) DiskUsageHandler {
	handlersMu.RLock()
	defer handlersMu.RUnlock()
	if h, ok := handlers[name]; ok {
		return h
	}
	return nil
}
