package global

import (
	"os"

	"github.com/go-kit/log"
)

// global Log
var Logger log.Logger

func init() {
	w := log.NewSyncWriter(os.Stderr)
	Logger = log.NewLogfmtLogger(w)
}
