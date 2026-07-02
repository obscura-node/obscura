// Package swapbook is the decentralized liquidity layer for XMR↔Obscura atomic
// swaps (Block 15 — see docs/INVENTION_SWAPS.md): a peer-to-peer order book of
// signed, PoW-stamped, expiring swap offers gossiped over the existing network.
// There is no AMM (a trustless cross-chain AMM is impossible without a bridge);
// this is maker-taker / RFQ matching like UnstoppableSwap/Haveno — a taker picks
// a maker's offer and runs the atomic swap directly with them.
package swapbook

import (
	"encoding/binary"
	"errors"
	"sort"
	"sync"
	"time"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/blake2b"

	"obscura/pkg/commit"
	"obscura/pkg/config"
)

const (
	// OfferPoWBits is a small proof-of-work on each offer id, deterring mass
	// spam/sybil offers without any identity (anti-spam, per the brainstorm).
	OfferPoWBits = 12
	// MaxOfferTTL bounds how far in the future an offer may expire.
	MaxOfferTTL = 6 * time.Hour
	// MaxBookSize caps memory.
	MaxBookSize = 50000
	// MaxAssetLen bounds an asset ticker (audit fix: cap variable-length fields
	// so the signed message cannot grow unboundedly and stays cheap to validate).
	MaxAssetLen = 16
)

// validAsset enforces an allowlist of characters for asset tickers (audit fix:
// reject control bytes — notably NUL — and out-of-range lengths so that asset
// strings carry no structural ambiguity).
func validAsset(s string) bool {
	if len(s) == 0 || len(s) > MaxAssetLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

// Offer is a maker's signed intent to swap GiveAmount of GiveAsset for
// GetAmount of GetAsset, valid until Expiry. Maker is the maker's contact/pubkey
// (also used to verify the signature). Nonce carries the anti-spam PoW.
type Offer struct {
	Maker      []byte // 32B maker pubkey (ed25519)
	GiveAsset  string // e.g. "OBX" or "XMR"
	GetAsset   string
	GiveAmount uint64
	GetAmount  uint64
	Expiry     int64 // unix seconds
	Nonce      uint64
	Sig        []byte // 64B Schnorr signature by Maker over Core()
}

// Core is the canonical signed/hashed bytes (everything except Sig).
//
// Audit fix: every variable-length field is length-prefixed (uint32 big-endian
// length followed by the bytes) instead of NUL-delimited. NUL delimiting was
// ambiguous — an asset string containing a NUL, or shifting bytes across the
// Maker/asset boundaries, could let two distinct offers serialize to identical
// signed bytes (signed-message ambiguity). Length-prefixing makes the encoding
// injective, so the signature commits to exactly one offer.
func (o *Offer) Core() []byte {
	var b []byte
	putB := func(p []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		b = append(b, l[:]...)
		b = append(b, p...)
	}
	putB(o.Maker)
	putB([]byte(o.GiveAsset))
	putB([]byte(o.GetAsset))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], o.GiveAmount)
	b = append(b, n[:]...)
	binary.BigEndian.PutUint64(n[:], o.GetAmount)
	b = append(b, n[:]...)
	binary.BigEndian.PutUint64(n[:], uint64(o.Expiry))
	b = append(b, n[:]...)
	binary.BigEndian.PutUint64(n[:], o.Nonce)
	b = append(b, n[:]...)
	return b
}

// ID is the offer identifier (also the PoW target).
func (o *Offer) ID() [32]byte { return blake2b.Sum256(o.Core()) }

func leadingZeroBits(h [32]byte) int {
	n := 0
	for _, b := range h {
		if b == 0 {
			n += 8
			continue
		}
		for i := 7; i >= 0; i-- {
			if b&(1<<uint(i)) == 0 {
				n++
			} else {
				return n
			}
		}
	}
	return n
}

// Sign grinds the anti-spam PoW and signs the offer with the maker's key.
func (o *Offer) Sign(makerSecret *edwards25519.Scalar) {
	o.Maker = new(edwards25519.Point).ScalarBaseMult(makerSecret).Bytes()
	o.Sig = nil
	for o.Nonce = 0; ; o.Nonce++ {
		if leadingZeroBits(o.ID()) >= OfferPoWBits {
			break
		}
	}
	o.Sig = commit.Sign(makerSecret, o.Core()).Serialize()
}

// Verify checks the PoW, expiry window, and maker signature.
func (o *Offer) Verify(now time.Time) bool {
	if len(o.Maker) != 32 || len(o.Sig) != 64 {
		return false
	}
	if o.GiveAmount == 0 || o.GetAmount == 0 || o.GiveAsset == o.GetAsset {
		return false
	}
	// Audit fix: reject malformed asset tickers (empty, over-long, or containing
	// control/NUL bytes) before trusting the signed message.
	if !validAsset(o.GiveAsset) || !validAsset(o.GetAsset) {
		return false
	}
	// Settleability gate: reject any offer naming an asset with no real,
	// settleable swap leg (currently BTC — see config.SettleableAssets). This
	// keeps unsettleable offers from being admitted, taken, or gossiped on. The
	// syntactic validAsset check above still applies; this is the semantic one.
	if !config.IsSettleableAsset(o.GiveAsset) || !config.IsSettleableAsset(o.GetAsset) {
		return false
	}
	if o.Expiry <= now.Unix() || o.Expiry > now.Add(MaxOfferTTL).Unix() {
		return false
	}
	if leadingZeroBits(o.ID()) < OfferPoWBits {
		return false
	}
	sig, err := commit.ParseFullSig(o.Sig)
	if err != nil {
		return false
	}
	return commit.VerifyFull(o.Maker, o.Core(), sig)
}

// Serialize encodes an offer for the wire.
func (o *Offer) Serialize() []byte {
	var b []byte
	putB := func(p []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		b = append(b, l[:]...)
		b = append(b, p...)
	}
	putB(o.Maker)
	putB([]byte(o.GiveAsset))
	putB([]byte(o.GetAsset))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], o.GiveAmount)
	b = append(b, n[:]...)
	binary.BigEndian.PutUint64(n[:], o.GetAmount)
	b = append(b, n[:]...)
	binary.BigEndian.PutUint64(n[:], uint64(o.Expiry))
	b = append(b, n[:]...)
	binary.BigEndian.PutUint64(n[:], o.Nonce)
	b = append(b, n[:]...)
	putB(o.Sig)
	return b
}

// ParseOffer decodes a wire offer.
func ParseOffer(data []byte) (*Offer, error) {
	pos := 0
	getB := func() ([]byte, error) {
		if pos+4 > len(data) {
			return nil, errors.New("swapbook: short offer")
		}
		n := int(binary.BigEndian.Uint32(data[pos:]))
		pos += 4
		if n < 0 || n > 1024 || pos+n > len(data) {
			return nil, errors.New("swapbook: bad offer field")
		}
		v := data[pos : pos+n]
		pos += n
		return v, nil
	}
	getU64 := func() (uint64, error) {
		if pos+8 > len(data) {
			return 0, errors.New("swapbook: short u64")
		}
		v := binary.BigEndian.Uint64(data[pos:])
		pos += 8
		return v, nil
	}
	o := &Offer{}
	var err error
	if o.Maker, err = getB(); err != nil {
		return nil, err
	}
	ga, err := getB()
	if err != nil {
		return nil, err
	}
	o.GiveAsset = string(ga)
	gt, err := getB()
	if err != nil {
		return nil, err
	}
	o.GetAsset = string(gt)
	if o.GiveAmount, err = getU64(); err != nil {
		return nil, err
	}
	if o.GetAmount, err = getU64(); err != nil {
		return nil, err
	}
	exp, err := getU64()
	if err != nil {
		return nil, err
	}
	o.Expiry = int64(exp)
	if o.Nonce, err = getU64(); err != nil {
		return nil, err
	}
	if o.Sig, err = getB(); err != nil {
		return nil, err
	}
	return o, nil
}

// Book is a thread-safe set of live offers.
type Book struct {
	mu     sync.Mutex
	offers map[[32]byte]*Offer
}

// NewBook creates an empty order book.
func NewBook() *Book { return &Book{offers: make(map[[32]byte]*Offer)} }

// Add verifies and inserts an offer; returns true if it was new.
func (b *Book) Add(o *Offer) (bool, error) {
	if !o.Verify(time.Now()) {
		// Distinguish the settleability rejection (a syntactically valid offer on
		// a gated asset such as BTC) from a generic invalid-offer failure, so the
		// caller/logs can tell WHY it was refused. The full Verify gate is still
		// authoritative; this is purely a clearer diagnostic.
		if !config.IsSettleableAsset(o.GiveAsset) || !config.IsSettleableAsset(o.GetAsset) {
			return false, errors.New("swapbook: asset not settleable (BTC is disabled; see config.SettleableAssets)")
		}
		return false, errors.New("swapbook: invalid offer")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.addLocked(o, false)
}

// AddPostOnly is Add with POST-ONLY semantics: the offer is rejected (without
// being admitted or gossiped) if it would CROSS the existing top-of-book — i.e.
// if a taker on the opposite side could already fill against it at the maker's
// own rate or better. A post-only maker wants to be a passive liquidity provider
// and never a taker, so a crossing quote (which would immediately execute) is an
// error rather than silently becoming an aggressive order. Post-only is a SUBMIT-
// TIME policy, not part of the signed offer terms (Core() stays injective and the
// signature unchanged), so the same signed offer can be posted either way.
func (b *Book) AddPostOnly(o *Offer) (bool, error) {
	if !o.Verify(time.Now()) {
		if !config.IsSettleableAsset(o.GiveAsset) || !config.IsSettleableAsset(o.GetAsset) {
			return false, errors.New("swapbook: asset not settleable (BTC is disabled; see config.SettleableAssets)")
		}
		return false, errors.New("swapbook: invalid offer")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.addLocked(o, true)
}

// addLocked is the shared insert body. Caller MUST hold b.mu. When postOnly is
// set it rejects an offer that would cross the opposite top-of-book.
func (b *Book) addLocked(o *Offer, postOnly bool) (bool, error) {
	b.pruneLocked()
	id := o.ID()
	if _, ok := b.offers[id]; ok {
		return false, nil
	}
	if len(b.offers) >= MaxBookSize {
		return false, errors.New("swapbook: full")
	}
	// Anti-flood: bound how many live offers any single maker may hold so one
	// maker (even one willing to grind the offer PoW) cannot pad the book and
	// distort depth/VWAP. See MaxOffersPerMaker for the limits of this defense.
	if n := b.countMakerLocked(o.Maker); n >= MaxOffersPerMaker {
		return false, errors.New("swapbook: maker offer cap reached")
	}
	if postOnly && b.crossesLocked(o) {
		return false, errors.New("swapbook: post-only offer would cross top-of-book")
	}
	b.offers[id] = o
	return true, nil
}

// crossesLocked reports whether maker offer o would immediately match against an
// existing OPPOSITE-side offer at o's rate or better. o gives o.GiveAsset and
// wants o.GetAsset; the opposite side is offers giving o.GetAsset for o.GiveAsset.
// o "crosses" if such an opposite offer's price makes the round-trip non-losing
// for a taker, i.e. opp.GiveAmount/opp.GetAmount >= o.GetAmount/o.GiveAmount.
// Caller MUST hold b.mu.
func (b *Book) crossesLocked(o *Offer) bool {
	for _, opp := range b.offers {
		if opp.GiveAsset != o.GetAsset || opp.GetAsset != o.GiveAsset {
			continue
		}
		if opp.GiveAmount == 0 || opp.GetAmount == 0 {
			continue
		}
		// opp's taker-rate (opp.GiveAmount per opp.GetAmount, in o.GetAsset per
		// o.GiveAsset units) >= o's ask (o.GetAmount per o.GiveAmount) means a taker
		// could profit/round-trip → o crosses. Compare exactly via cmpRate.
		if cmpRate(opp.GiveAmount, opp.GetAmount, o.GetAmount, o.GiveAmount) >= 0 {
			return true
		}
	}
	return false
}

func (b *Book) pruneLocked() {
	now := time.Now().Unix()
	for id, o := range b.offers {
		if o.Expiry <= now {
			delete(b.offers, id)
		}
	}
}

// countMakerLocked counts live offers owned by maker. Caller must hold b.mu and
// should pruneLocked first so expired offers don't count against the cap.
func (b *Book) countMakerLocked(maker []byte) int {
	if len(maker) != 32 {
		return 0
	}
	n := 0
	for _, o := range b.offers {
		if len(o.Maker) == 32 && string(o.Maker) == string(maker) {
			n++
		}
	}
	return n
}

// List returns all live offers.
func (b *Book) List() []*Offer {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked()
	out := make([]*Offer, 0, len(b.offers))
	for _, o := range b.offers {
		out = append(out, o)
	}
	return out
}

// Best returns the offer giving `getAsset` for `giveAsset` (from the taker's
// view: taker gives giveAsset, wants getAsset) at the best price for the taker,
// i.e. the maker offering the most getAsset per giveAsset.
func (b *Book) Best(takerGives, takerWants string) *Offer {
	cands := b.List()
	var best *Offer
	for _, o := range cands {
		// maker gives o.GiveAsset, wants o.GetAsset; match: maker.Give==takerWants
		if o.GiveAsset != takerWants || o.GetAsset != takerGives {
			continue
		}
		// taker receives o.GiveAmount for paying o.GetAmount → rate give/get, compared
		// exactly (cmpRate) rather than via float64 division, which loses precision
		// above ~9007 XNO/OBX offer units and can misrank near-equal offers.
		if best == nil || cmpRate(o.GiveAmount, o.GetAmount, best.GiveAmount, best.GetAmount) > 0 {
			best = o
		}
	}
	return best
}

// PairLiquidity aggregates the live order book for one directed pair
// (give_asset -> get_asset, from the MAKER's orientation: makers give GiveAsset
// and want GetAsset). It is a pure read used by the /liquidity RPC so the UI can
// reflect available depth and the best rate without re-deriving it client-side.
type PairLiquidity struct {
	Pair      string // "GIVE/GET", e.g. "OBX/XNO"
	GiveAsset string
	GetAsset  string
	TotalGive uint64 // Σ GiveAmount across the pair's live offers (atomic units)
	TotalGet  uint64 // Σ GetAmount across the pair's live offers (atomic units)
	Offers    int    // number of live offers on this pair
	Makers    int    // distinct maker pubkeys on this pair
	BestRate  string // best (highest get/give) rate, raw "get/give" decimal string
}

// Liquidity returns one PairLiquidity row per distinct directed (GiveAsset,
// GetAsset) pair currently live in the book, plus the global offer + maker
// counts. Rows are sorted by pair string for stable display. Best rate mirrors
// the taker-favourable orientation used elsewhere (most get per give); it is
// emitted as the raw atomic get/give ratio so the frontend applies per-asset
// decimals exactly as it does for OfferJSON.Rate / PairPrice.Rate.
func (b *Book) Liquidity() (pairs []PairLiquidity, totalOffers, totalMakers int) {
	live := b.List() // prunes expired
	type agg struct {
		give, get uint64
		offers    int
		makers    map[string]struct{}
		bestNum   uint64 // best rate get/give as a fraction bestNum/bestDen
		bestDen   uint64
	}
	byPair := map[string]*agg{}
	allMakers := map[string]struct{}{}
	for _, o := range live {
		key := o.GiveAsset + "/" + o.GetAsset
		a := byPair[key]
		if a == nil {
			a = &agg{makers: map[string]struct{}{}}
			byPair[key] = a
		}
		a.give += o.GiveAmount
		a.get += o.GetAmount
		a.offers++
		a.makers[string(o.Maker)] = struct{}{}
		allMakers[string(o.Maker)] = struct{}{}
		// best taker rate on this pair = max(get/give). Compare via cross-multiply
		// to avoid float rounding: get/give > bestNum/bestDen iff get*bestDen >
		// bestNum*give. The very first offer seeds the best.
		if o.GiveAmount != 0 {
			if a.bestDen == 0 || cmpRate(o.GetAmount, o.GiveAmount, a.bestNum, a.bestDen) > 0 {
				a.bestNum, a.bestDen = o.GetAmount, o.GiveAmount
			}
		}
		totalOffers++
	}
	for key, a := range byPair {
		parts := splitPair(key)
		best := "0"
		if a.bestDen != 0 {
			best = ratioString(a.bestNum, a.bestDen)
		}
		pairs = append(pairs, PairLiquidity{
			Pair:      key,
			GiveAsset: parts[0],
			GetAsset:  parts[1],
			TotalGive: a.give,
			TotalGet:  a.get,
			Offers:    a.offers,
			Makers:    len(a.makers),
			BestRate:  best,
		})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].Pair < pairs[j].Pair })
	return pairs, totalOffers, len(allMakers)
}

// splitPair splits a "GIVE/GET" key back into its two assets (always exactly one
// '/' since both assets are validAsset-restricted and never contain '/').
func splitPair(key string) [2]string {
	for i := 0; i < len(key); i++ {
		if key[i] == '/' {
			return [2]string{key[:i], key[i+1:]}
		}
	}
	return [2]string{key, ""}
}

// ratioString renders num/den as a decimal string with enough precision for a
// raw atomic rate, trimming trailing zeros. It avoids importing strconv float
// formatting quirks by using a fixed high-precision then trim.
func ratioString(num, den uint64) string {
	if den == 0 {
		return "0"
	}
	// integer part
	ip := num / den
	rem := num % den
	out := strconvU(ip)
	if rem == 0 {
		return out
	}
	out += "."
	// up to 18 fractional digits, then trim trailing zeros.
	frac := make([]byte, 0, 18)
	for i := 0; i < 18 && rem != 0; i++ {
		rem *= 10
		frac = append(frac, byte('0'+rem/den))
		rem %= den
	}
	// trim trailing zeros
	for len(frac) > 0 && frac[len(frac)-1] == '0' {
		frac = frac[:len(frac)-1]
	}
	return out + string(frac)
}

// strconvU renders a uint64 as decimal (avoids pulling strconv just for this).
func strconvU(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// Size returns the number of live offers.
func (b *Book) Size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.offers)
}

// SortedByID returns offers in deterministic id order (for stable display/tests).
func (b *Book) SortedByID() []*Offer {
	out := b.List()
	sort.Slice(out, func(i, j int) bool {
		a, c := out[i].ID(), out[j].ID()
		for k := range a {
			if a[k] != c[k] {
				return a[k] < c[k]
			}
		}
		return false
	})
	return out
}
