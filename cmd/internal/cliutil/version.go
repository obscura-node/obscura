// Package cliutil holds small, shared command-line helpers for the obscura-*
// binaries: the canonical --version string, key=value config-file loading,
// leveled log filtering, and shell-completion script generation.
//
// It is an *internal* package under cmd/, so only the CLI binaries can import
// it — it deliberately adds NO new public API surface to the coin.
package cliutil

import (
	"fmt"
	"runtime"

	"obscura/pkg/config"
	"obscura/pkg/p2p"
)

// VersionString returns the canonical one-line version banner every
// obscura-* binary prints for `--version` / `version`, e.g.
//
//	obscura-node 1.0.0 (network=mainnet, go=go1.25.0)
//
// The release version is the single existing source of truth,
// p2p.SoftwareVersion (what nodes advertise in the P2P hello).
func VersionString(binName string) string {
	return fmt.Sprintf("%s %s (network=%s, go=%s)", binName, p2p.SoftwareVersion, config.Network, runtime.Version())
}

// IsVersionArg reports whether a raw argument asks for the version: the
// `version` subcommand or the --version / -version flag spellings.
func IsVersionArg(arg string) bool {
	return arg == "version" || arg == "--version" || arg == "-version"
}
