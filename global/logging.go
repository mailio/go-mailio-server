package global

import (
	"os"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

// global Log
var Logger log.Logger

func init() {
	w := log.NewSyncWriter(os.Stderr)
	Logger = log.NewLogfmtLogger(w)
	Logger = level.NewFilter(Logger, level.AllowError())
	Logger = log.With(Logger, "caller", log.DefaultCaller)

	// example logging with levels:
	// level.Error(global.Logger).Log("err", errors.New("bad data"))
	// level.Info(global.Logger).Log("event", "data saved")
	// level.Debug(global.Logger).Log("next item", 17) // filtered
}
