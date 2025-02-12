package global

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

// ANSI color codes.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
)

// stdoutLoggerAdapter implements the go-kit log.Logger interface,
// printing formatted, colored log messages to stdout/stderr.
type stdoutLoggerAdapter struct {
	ctx context.Context
}

// global Log
var Logger log.Logger

// findCaller dynamically finds the first non-logging caller in the stack.
func findCaller() (string, int) {
	for i := 2; i < 15; i++ { // Start from 2 to skip logging itself.
		_, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		// Skip logging-related files.
		if !isLoggingFile(file) {
			return file, line
		}
	}
	return "unknown", 0
}

// isLoggingFile checks if the given file belongs to the logging framework.
func isLoggingFile(file string) bool {
	return contains(file, "go-kit") || contains(file, "log.go") || contains(file, "gin-gonic")
}

// contains checks if substr is contained in str.
func contains(str, substr string) bool {
	// Simple (recursive) substring check.
	if len(str) < len(substr) {
		return false
	}
	if str[:len(substr)] == substr {
		return true
	}
	return contains(str[1:], substr)
}

// Log processes key/value pairs, attaches caller info and a stack trace (for errors),
// and prints a formatted, colored log line to stdout or stderr.
func (c *stdoutLoggerAdapter) Log(keyvals ...interface{}) error {
	payload := make(map[string]interface{})
	// Default severity is "info".
	severity := "info"
	includeStack := false

	// Find caller information.
	file, line := findCaller()

	// Process key/value pairs.
	for i := 0; i < len(keyvals); i++ {
		// Try to extract a string key.
		key, ok := keyvals[i].(string)
		if !ok {
			payload[fmt.Sprintf("extra_%d", i)] = keyvals[i]
			continue
		}
		var value interface{} = "(missing value)"
		if i+1 < len(keyvals) {
			value = keyvals[i+1]
			i++ // Move to the next pair.
		}

		if key == "level" {
			// Handle level detection. We support both level.Value and plain strings.
			var levelStr string
			if lv, ok := value.(level.Value); ok {
				levelStr = lv.String()
			} else if s, ok := value.(string); ok {
				levelStr = s
			}
			severity = levelStr
			// For errors/critical logs, we want to include a stack trace.
			if levelStr == "error" || levelStr == "critical" {
				includeStack = true
			}
			payload[key] = levelStr
		} else {
			payload[key] = value
		}
	}

	if severity == "" {
		severity = "info"
	}

	// Automatically add caller info.
	payload["caller"] = fmt.Sprintf("%s:%d", file, line)

	// Add a stack trace if needed and not already provided.
	if includeStack && payload["stack"] == nil {
		payload["stack"] = string(debug.Stack())
	}

	// Choose a color and output stream based on severity.
	var color string
	out := os.Stdout
	switch severity {
	case "error", "critical":
		color = colorRed
		out = os.Stderr
	case "warn", "warning":
		color = colorYellow
	case "info":
		color = colorGreen
	default:
		color = ""
	}

	// Build the formatted message.
	ts := time.Now().Format(time.RFC3339)
	callerStr, _ := payload["caller"].(string)
	msg := fmt.Sprintf("%s [%s] %s", ts, severity, callerStr)
	// Append additional key/value pairs (skipping "caller" and "level").
	for k, v := range payload {
		if k == "caller" || k == "level" {
			continue
		}
		msg += fmt.Sprintf(" %s=%v", k, v)
	}
	// If a stack trace was added, ensure it appears on its own line.
	if includeStack {
		if stack, ok := payload["stack"].(string); ok {
			msg += "\n" + stack
		}
	}

	// Print the message with the chosen color, then reset.
	fmt.Fprintln(out, color+msg+colorReset)
	return nil
}

// join is a simple helper to join string slices.
func join(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	s := parts[0]
	for _, part := range parts[1:] {
		s += sep + part
	}
	return s
}

// NewStdLogger creates and returns a new logger that writes colored logs to stdout/stderr.
// NewStdLogger creates a new logger that prints colored logs to stdout/stderr.
func NewStdLogger() (log.Logger, func() error, error) {
	ctx := context.Background()
	adapter := &stdoutLoggerAdapter{
		ctx: ctx,
	}
	logger := level.NewFilter(adapter, level.AllowAll())
	Logger = logger
	// Return a no-op close function.
	return logger, func() error { return nil }, nil
}

func init() {
	NewStdLogger()
}
