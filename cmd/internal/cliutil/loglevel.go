package cliutil

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
)

// Log levels accepted by --log-level / OBX_LOG_LEVEL.
const (
	LogQuiet = "quiet"
	LogInfo  = "info"
	LogDebug = "debug"
)

// ResolveLogLevel picks the effective level from the flag value (highest
// precedence), then OBX_LOG_LEVEL, then the default "info". It returns an
// error for anything that is not quiet|info|debug.
func ResolveLogLevel(flagValue string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(flagValue))
	if v == "" {
		v = strings.ToLower(strings.TrimSpace(os.Getenv("OBX_LOG_LEVEL")))
	}
	if v == "" {
		v = LogInfo
	}
	switch v {
	case LogQuiet, LogInfo, LogDebug:
		return v, nil
	}
	return "", fmt.Errorf("bad log level %q (want quiet|info|debug)", v)
}

// SetupLogging installs a level filter over the standard logger's output.
//
// WHAT IT HONESTLY DOES (a line filter, not a structured-logging rewrite):
//   - info  (default): passes every log line unchanged — identical to today.
//   - quiet: passes ONLY (a) the very first log line (the startup banner, so
//     an operator can still see what started) and (b) lines containing one of
//     the severity markers ERROR / WARN / FATAL / SECURITY / panic
//     (case-sensitive, matching the codebase's existing conventions).
//     Everything else is dropped.
//   - debug: passes every line, exactly like info. The per-component verbose
//     traces (OBX_P2P_DEBUG, OBX_SWAP_DEBUG) are read at package init — before
//     main runs — so --log-level=debug CANNOT retroactively enable them; set
//     those env vars alongside if you want component tracing. debug exists so
//     scripts can express intent and future leveled logs have a home.
//
// It returns the resolved level so the caller can log/announce it.
func SetupLogging(flagValue string) (string, error) {
	level, err := ResolveLogLevel(flagValue)
	if err != nil {
		return "", err
	}
	if level == LogQuiet {
		log.SetOutput(NewLevelWriter(os.Stderr, level))
	}
	return level, nil
}

// quietMarkers are the substrings that keep a line visible at level quiet.
var quietMarkers = []string{"ERROR", "WARN", "FATAL", "SECURITY", "panic"}

// levelWriter filters whole log writes (the stdlib logger emits one Write per
// log line) by severity markers. Concurrency-safe.
type levelWriter struct {
	mu    sync.Mutex
	w     io.Writer
	level string
	wrote bool // first write (startup banner) always passes at quiet
}

// NewLevelWriter wraps w with the level filter described in SetupLogging.
func NewLevelWriter(w io.Writer, level string) io.Writer {
	return &levelWriter{w: w, level: level}
}

func (lw *levelWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	if lw.level != LogQuiet {
		return lw.w.Write(p)
	}
	if !lw.wrote {
		lw.wrote = true
		return lw.w.Write(p)
	}
	s := string(p)
	for _, m := range quietMarkers {
		if strings.Contains(s, m) {
			return lw.w.Write(p)
		}
	}
	// dropped: report success so the logger never errors on suppressed lines.
	return len(p), nil
}
