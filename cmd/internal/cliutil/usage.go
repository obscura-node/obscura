package cliutil

import (
	"flag"
	"fmt"
	"strings"
)

// UsageSection names a group of flags for GroupedUsage.
type UsageSection struct {
	Title string
	Flags []string // long flag names, without dashes
}

// GroupedUsage renders a sectioned flag reference for fs instead of the flag
// package's flat alphabetical dump. Flags not claimed by any section are
// appended under "Other" so a newly added flag can never silently vanish from
// --help. Long per-flag doc comments are truncated to one line; the full text
// lives in docs/CLI.md and the source.
func GroupedUsage(fs *flag.FlagSet, bin, intro string, sections []UsageSection) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Usage: %s [flags]\n", bin)
	if intro != "" {
		fmt.Fprintf(&b, "%s\n", intro)
	}

	claimed := map[string]bool{}
	for _, sec := range sections {
		for _, n := range sec.Flags {
			claimed[n] = true
		}
	}
	var other []string
	fs.VisitAll(func(f *flag.Flag) {
		if !claimed[f.Name] {
			other = append(other, f.Name)
		}
	})
	all := sections
	if len(other) > 0 {
		all = append(all, UsageSection{Title: "Other", Flags: other})
	}

	for _, sec := range all {
		wrote := false
		for _, name := range sec.Flags {
			f := fs.Lookup(name)
			if f == nil {
				continue // section lists a flag this build doesn't have — skip
			}
			if !wrote {
				fmt.Fprintf(&b, "\n%s:\n", sec.Title)
				wrote = true
			}
			def := ""
			if f.DefValue != "" {
				def = fmt.Sprintf(" (default %s)", f.DefValue)
			}
			fmt.Fprintf(&b, "  --%s%s\n        %s\n", f.Name, def, oneLine(f.Usage, 110))
		}
	}
	return b.String()
}

// oneLine collapses usage text to a single line and truncates it.
func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > max {
		return string(r[:max-1]) + "…"
	}
	return s
}
