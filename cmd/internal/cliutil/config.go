package cliutil

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
)

// ConfigPathFromArgs returns the config-file path requested on the command
// line (`--config FILE`, `-config FILE`, `--config=FILE`, `-config=FILE`) or,
// when absent there, from the OBX_CONFIG environment variable. Empty string
// means "no config file requested".
//
// It exists because the config file must be applied BEFORE flag.Parse (so the
// file only supplies defaults and explicit flags win), which means the
// --config flag itself has to be discovered by scanning the raw arguments.
func ConfigPathFromArgs(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		name, val, hasVal := strings.Cut(a, "=")
		if name != "--config" && name != "-config" {
			continue
		}
		if hasVal {
			return val
		}
		if i+1 < len(args) {
			return args[i+1]
		}
		return ""
	}
	return os.Getenv("OBX_CONFIG")
}

// ApplyConfigFile reads a simple `key = value` config file and applies each
// entry to the matching long flag in fs as a NEW DEFAULT. Call it BEFORE
// fs.Parse: Parse then overwrites any key also given explicitly on the
// command line, so the precedence is
//
//	command-line flag  >  config file  >  built-in default
//
// File format (documented in docs/CLI.md):
//   - one `key = value` (or `key=value`) per line; keys are the long flag
//     names without dashes (e.g. `mine = true`, `mine-address = obx1...`)
//   - blank lines and lines starting with `#` are ignored; a trailing
//     ` # comment` after the value is NOT stripped (values may contain #)
//   - values may be wrapped in single or double quotes, which are stripped
//   - booleans use the flag package's forms: true/false/1/0
//
// Unknown keys and unparseable values are hard errors (a typo in a config
// file must never be silently ignored). The `config` key itself is rejected
// (a config file cannot chain-load another config file).
func ApplyConfigFile(fs *flag.FlagSet, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("config file: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("%s:%d: not a `key = value` line: %q", path, lineNo, line)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		// strip one level of matching quotes around the value
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		if key == "" {
			return fmt.Errorf("%s:%d: empty key", path, lineNo)
		}
		if key == "config" {
			return fmt.Errorf("%s:%d: a config file cannot set `config` (no chain-loading)", path, lineNo)
		}
		fl := fs.Lookup(key)
		if fl == nil {
			return fmt.Errorf("%s:%d: unknown option %q (keys are long flag names, e.g. `mine`, `mine-address`)", path, lineNo, key)
		}
		// Set the flag's VALUE directly (not fs.Set): the flag is not marked
		// as "explicitly set", so it behaves exactly like a changed default —
		// fs.Parse still overwrites it with any command-line value, and
		// fs.Visit does not report it.
		if err := fl.Value.Set(val); err != nil {
			return fmt.Errorf("%s:%d: bad value for %q: %v", path, lineNo, key, err)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("config file %s: %w", path, err)
	}
	return nil
}
