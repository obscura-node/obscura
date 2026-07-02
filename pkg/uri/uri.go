// Package uri implements BIP21-style payment URIs for Obscura, e.g.
//
//	obscura:<address>?amount=1.5&label=Coffee
//
// These encode a payment request as a single string suitable for QR codes and
// "pay" links, so a payer can scan once instead of copying an address and typing
// an amount separately.
package uri

import (
	"errors"
	"net/url"
	"strings"
)

// Scheme is the URI scheme.
const Scheme = "obscura"

// Format builds a payment URI. amount (decimal OBX, as a string) and label are
// optional — pass "" to omit them.
func Format(addr, amount, label string) string {
	// audit: ROUND2 [129] percent-encode the address before placing it in the
	// opaque component. url.URL.String() writes Opaque verbatim, so an address
	// containing '?', '#', '&' etc. would otherwise inject URI structure (extra
	// query params / a fragment). Parse symmetrically unescapes (see below).
	u := url.URL{Scheme: Scheme, Opaque: url.PathEscape(addr)}
	q := url.Values{}
	if amount != "" {
		q.Set("amount", amount)
	}
	if label != "" {
		q.Set("label", label)
	}
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// Parse decodes a payment URI into its address and optional amount/label.
func Parse(s string) (addr, amount, label string, err error) {
	if !strings.HasPrefix(s, Scheme+":") {
		return "", "", "", errors.New("uri: not an obscura: URI")
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", "", "", err
	}
	addr = u.Opaque
	if addr != "" {
		// audit: ROUND2 [129] symmetric unescape of the opaque component, which
		// url.Parse leaves percent-encoded (unlike Host/Path, which it decodes).
		if dec, derr := url.PathUnescape(addr); derr == nil {
			addr = dec
		}
	} else {
		// tolerate the "obscura://addr" form too
		addr = u.Host
		if addr == "" {
			addr = strings.TrimPrefix(u.Path, "/")
		}
	}
	if addr == "" {
		return "", "", "", errors.New("uri: missing address")
	}
	q := u.Query()
	return addr, q.Get("amount"), q.Get("label"), nil
}

// IsURI reports whether s looks like an obscura: payment URI.
func IsURI(s string) bool { return strings.HasPrefix(s, Scheme+":") }
