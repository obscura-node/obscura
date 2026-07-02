package swapbook

import (
	"errors"
	"sort"
	"sync"
	"time"

	"obscura/pkg/config"
)

// fillstate.go turns the order book from an RFQ billboard into a real
// matching/fill engine. It adds, ALL off-chain and non-consensus (offers stay
// gossiped P2P RFQ quotes — see swapbook.go's package doc):
//
//   - mutable per-offer FILL STATE (RemainingGive/RemainingGet + Status) tracked
//     in a sidecar map keyed by offer ID, so the signed Offer stays IMMUTABLE and
//     its signature stays valid;
//   - a RESERVE / COMMIT / RELEASE lifecycle that lets a taker atomically claim
//     liquidity across multiple rungs before running the (slow, async) settlement
//     swap, then finalize it on success or restore it on failure/timeout;
//   - an executed-TRADE TAPE (ring buffer) joined to on-chain settlement by
//     SwapKey, plus OHLCV candles and 24h stats derived from it;
//   - order-type semantics (market / IOC / FOK / post-only) over the reserve walk.
//
// CONCURRENCY: all fill-state mutation happens under b.mu (the same mutex that
// guards b.offers), so a double-take of the same offer cannot oversell — the two
// Reserve calls serialize and the second sees the decremented Remaining.

// Status is the lifecycle of a live offer's fillable remainder.
type Status uint8

const (
	StatusOpen      Status = iota // untouched: Remaining == full
	StatusPartial                 // partially reserved/filled: 0 < Remaining < full
	StatusFilled                  // fully consumed: Remaining == 0
	StatusCancelled               // cancelled by the maker (offer removed)
)

func (s Status) String() string {
	switch s {
	case StatusOpen:
		return "open"
	case StatusPartial:
		return "partial"
	case StatusFilled:
		return "filled"
	case StatusCancelled:
		return "cancelled"
	default:
		return "unknown"
	}
}

// fill is the mutable sidecar fill state for one signed offer. The signed Offer
// is never mutated (so its signature stays valid); this tracks the consumable
// remainder. RemainingGet is the maker's getAsset capacity still claimable (units
// the TAKER can pay into this offer); RemainingGive is the maker's giveAsset still
// deliverable (units the TAKER can still receive). They shrink together at the
// offer's fixed rate. `reserved` is the portion currently held by open (not yet
// committed or released) reservations — it is subtracted from Remaining at
// Reserve time and either committed (kept) or restored (released).
type fill struct {
	get    uint64 // full GetAmount (immutable copy, for status derivation)
	give   uint64 // full GiveAmount
	remGet uint64 // getAsset capacity still claimable (taker pays this)
	remGve uint64 // giveAsset still deliverable (taker receives this)
	status Status
}

// Reservation is one rung of a multi-rung reserve: it pins a slice of a single
// offer's remainder so the taker can settle it without another taker racing in.
// Pay is the giveAsset the taker commits to this rung; Recv is the getAsset the
// taker receives for it (both at the offer's fixed rate). It is returned to the
// taker and later handed back to CommitTrade or ReleaseReservation verbatim.
type Reservation struct {
	OfferID [32]byte
	Maker   []byte // 32B maker pubkey (for the trade tape + STP audit)
	Pay     uint64 // giveAsset the taker pays into this rung
	Recv    uint64 // getAsset the taker receives from this rung
}

// Trade is one executed fill recorded on the tape. Price is the raw atomic
// get/give rate string (frontend applies per-asset decimals, like everywhere
// else). SwapKey joins to the on-chain settlement event when known ("" until the
// settlement leg mints one). Give/Get are the taker's leg totals for this trade.
type Trade struct {
	Pair    string // "GIVE/GET" from the taker's orientation (taker gives/gets)
	Price   string // raw atomic Get/Give rate string
	Give    uint64 // total giveAsset the taker paid
	Get     uint64 // total getAsset the taker received
	Maker   string // hex maker pubkey of the (best-rung) maker, "" if mixed
	Taker   string // hex taker pubkey
	SwapKey string // hex on-chain swap key, "" until settlement joins it
	Time    int64  // unix seconds the trade committed
}

const tradeTapeCap = 5000

// Sidecar holds the per-book fill state + trade tape. It lives ON the Book (see
// the embedded init in NewBook via ensureFill) but is split into its own struct
// so the Book's original fields stay untouched. Guarded by the Book's b.mu.
type sidecar struct {
	fills  map[[32]byte]*fill
	trades []Trade // ring buffer, newest appended at the tail; trimmed to cap
}

// fillMu and fillState are attached lazily to a Book the first time fill state is
// needed. We keep them in a package-level map keyed by *Book so we do not have to
// edit the Book struct literal in swapbook.go (Book is constructed via NewBook
// there). This keeps the change additive and the signed-offer path untouched.
var (
	scMu  sync.Mutex
	scMap = map[*Book]*sidecar{}
)

// sc returns this book's sidecar, creating it on first use. Caller need NOT hold
// b.mu; the scMu guards the registry. The returned *sidecar's fields are guarded
// by b.mu (the caller holds it when mutating fills/trades).
func (b *Book) sc() *sidecar {
	scMu.Lock()
	s := scMap[b]
	if s == nil {
		s = &sidecar{fills: map[[32]byte]*fill{}}
		scMap[b] = s
	}
	scMu.Unlock()
	return s
}

// fillFor returns (creating if absent) the fill state for offer id, seeding it
// from the live offer o. Caller MUST hold b.mu. A nil o with no existing fill
// returns nil (offer gone).
func (b *Book) fillForLocked(s *sidecar, id [32]byte, o *Offer) *fill {
	f := s.fills[id]
	if f != nil {
		return f
	}
	if o == nil {
		return nil
	}
	f = &fill{
		get: o.GetAmount, give: o.GiveAmount,
		remGet: o.GetAmount, remGve: o.GiveAmount,
		status: StatusOpen,
	}
	s.fills[id] = f
	return f
}

// FillState is a read-only snapshot of one offer's fill state for the RPC layer.
type FillState struct {
	RemainingGive uint64
	RemainingGet  uint64
	Status        Status
}

// OfferFill returns the fill state for offer id. found is false when the offer is
// not live in the book. An offer that has never been reserved reports its full
// amounts as Remaining and StatusOpen.
func (b *Book) OfferFill(id [32]byte) (fs FillState, found bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked()
	o, ok := b.offers[id]
	if !ok {
		return FillState{}, false
	}
	s := b.sc()
	f := b.fillForLocked(s, id, o)
	return FillState{RemainingGive: f.remGve, RemainingGet: f.remGet, Status: f.status}, true
}

// ---- reserve / commit / release --------------------------------------------

// ErrNoLiquidity is returned by Reserve when no matching offer can fill any of
// the requested size (after STP + dust filtering).
var ErrNoLiquidity = errors.New("swapbook: no matching liquidity")

// ErrDust is returned when the requested size is below the per-asset MinOrderSize.
var ErrDust = errors.New("swapbook: order below minimum size (dust)")

// ErrFOKUnfillable is returned by a FOK reserve when the book cannot fill the
// FULL requested size (all-or-nothing).
var ErrFOKUnfillable = errors.New("swapbook: FOK order cannot be filled in full")

// ReserveOpts tunes a reserve walk.
type ReserveOpts struct {
	// TakerPub is the taker's 32B pubkey; offers from this maker are SKIPPED
	// (self-trade prevention). May be nil to disable STP.
	TakerPub []byte
	// FOK, when true, makes the reserve all-or-nothing: if the book cannot fill
	// the full `size`, nothing is reserved and ErrFOKUnfillable is returned. When
	// false the walk is IOC/market style: it reserves what it can and returns a
	// partial set (filledGive < size) without error.
	FOK bool
	// MinFillRate, when non-zero, is a slippage cap: a rung whose taker rate
	// (Recv/Pay = give/get of the offer) is BELOW this min is not reserved, and
	// the walk stops there (offers are best-first, so all deeper rungs are worse).
	// Expressed as a fraction MinFillRateNum/MinFillRateDen (getAsset per
	// giveAsset). Zero den disables the cap.
	MinFillRateNum uint64
	MinFillRateDen uint64
}

// Reserve walks the live matching offers best-rate-first and atomically reserves
// up to `size` units of giveAsset across one or more rungs, decrementing each
// touched offer's Remaining under b.mu. It returns the reserved rungs, the
// volume-weighted filled rate as a (num,den) atomic fraction (getOut,giveIn), and
// an error only for hard failures (dust, FOK-unfillable, no liquidity at all).
//
// A partial fill (sum(Pay) < size) is NOT an error for a non-FOK reserve — the
// caller (IOC/market) takes what is available. The reserved liquidity is HELD
// (subtracted from each offer's Remaining) until the caller calls CommitTrade
// (finalize) or ReleaseReservation (restore). Self-trade offers (maker ==
// opts.TakerPub) are skipped. Dust (size < MinOrderSize[giveAsset]) is rejected.
func (b *Book) Reserve(giveAsset, getAsset string, size uint64, opts ReserveOpts) (res []Reservation, getOut, giveIn uint64, err error) {
	if size == 0 || !validAsset(giveAsset) || !validAsset(getAsset) || giveAsset == getAsset {
		return nil, 0, 0, ErrNoLiquidity
	}
	if size < config.MinOrderSizeFor(giveAsset) {
		return nil, 0, 0, ErrDust
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked()
	s := b.sc()

	side := b.matchingOffersLocked(giveAsset, getAsset)
	remaining := size
	for _, o := range side {
		if remaining == 0 {
			break
		}
		// Self-trade prevention: never fill a taker against their own maker offer.
		if len(opts.TakerPub) == 32 && len(o.Maker) == 32 && string(o.Maker) == string(opts.TakerPub) {
			continue
		}
		// Slippage cap: stop at the first rung worse than the floor (best-first).
		if opts.MinFillRateDen != 0 {
			if cmpRate(o.GiveAmount, o.GetAmount, opts.MinFillRateNum, opts.MinFillRateDen) < 0 {
				break
			}
		}
		id := o.ID()
		f := b.fillForLocked(s, id, o)
		if f.status == StatusFilled || f.status == StatusCancelled || f.remGet == 0 {
			continue
		}
		// The taker can pay up to this offer's remaining getAsset capacity.
		pay := f.remGet
		if pay > remaining {
			pay = remaining
		}
		if pay == 0 {
			continue
		}
		// floor(pay * GiveAmount / GetAmount) — never over-credit the taker.
		recv := mulDivFloor(pay, o.GiveAmount, o.GetAmount)
		if recv == 0 {
			continue // rate/pay so small the taker would receive nothing
		}
		// Decrement Remaining under the lock — this is the oversell guard.
		f.remGet -= pay
		if recv > f.remGve {
			recv = f.remGve // never deliver more than the maker has left
		}
		f.remGve -= recv
		if f.remGet == 0 || f.remGve == 0 {
			f.status = StatusFilled
		} else {
			f.status = StatusPartial
		}
		res = append(res, Reservation{
			OfferID: id,
			Maker:   append([]byte(nil), o.Maker...),
			Pay:     pay,
			Recv:    recv,
		})
		getOut += recv
		giveIn += pay
		remaining -= pay
	}

	if len(res) == 0 {
		return nil, 0, 0, ErrNoLiquidity
	}
	if opts.FOK && giveIn < size {
		// All-or-nothing: roll back everything we just reserved.
		b.releaseLocked(s, res)
		return nil, 0, 0, ErrFOKUnfillable
	}
	return res, getOut, giveIn, nil
}

// matchingOffersLocked is matchingOffers' body but assumes b.mu is held (it reads
// b.offers directly instead of via List(), which would re-lock). It prunes
// expired offers first, then returns the matchable side best-rate-first.
func (b *Book) matchingOffersLocked(giveAsset, getAsset string) []*Offer {
	b.pruneLocked()
	side := make([]*Offer, 0, len(b.offers))
	for _, o := range b.offers {
		if o.GiveAsset != getAsset || o.GetAsset != giveAsset {
			continue
		}
		if o.GiveAmount == 0 || o.GetAmount == 0 {
			continue
		}
		side = append(side, o)
	}
	sort.Slice(side, func(i, j int) bool {
		a, c := side[i], side[j]
		cmp := cmpRate(a.GiveAmount, a.GetAmount, c.GiveAmount, c.GetAmount)
		if cmp != 0 {
			return cmp > 0
		}
		ai, ci := a.ID(), c.ID()
		for k := range ai {
			if ai[k] != ci[k] {
				return ai[k] < ci[k]
			}
		}
		return false
	})
	return side
}

// ReleaseReservation restores the reserved liquidity to each offer's Remaining
// (e.g. the settlement swap failed or timed out). Reservations for offers that
// have since been cancelled/expired are silently dropped (their liquidity is
// gone). Safe to call once per reservation set.
func (b *Book) ReleaseReservation(res []Reservation) {
	if len(res) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.releaseLocked(b.sc(), res)
}

// releaseLocked restores reserved Pay/Recv to the offers' fill state. Caller MUST
// hold b.mu. It is clamped to the offer's full amount so a double-release can
// never inflate Remaining beyond the signed offer's size.
func (b *Book) releaseLocked(s *sidecar, res []Reservation) {
	for _, r := range res {
		f := s.fills[r.OfferID]
		if f == nil {
			continue // offer (and its fill) gone — nothing to restore
		}
		f.remGet += r.Pay
		if f.remGet > f.get {
			f.remGet = f.get
		}
		f.remGve += r.Recv
		if f.remGve > f.give {
			f.remGve = f.give
		}
		switch {
		case f.remGet >= f.get && f.remGve >= f.give:
			f.status = StatusOpen
		case f.remGet == 0 || f.remGve == 0:
			f.status = StatusFilled
		default:
			f.status = StatusPartial
		}
	}
}

// CommitTrade finalizes a reservation set: it leaves the Remaining decrement in
// place (the liquidity is consumed), marks each touched offer partial/filled, and
// appends ONE aggregate Trade to the tape joining all rungs of this taker fill.
// swapKey (hex, may be "") joins it to the on-chain settlement event. takerPub
// (hex, may be "") records the taker. It returns the recorded Trade.
func (b *Book) CommitTrade(res []Reservation, giveAsset, getAsset, swapKey, takerPub string) Trade {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sc()
	var give, get uint64
	maker := ""
	mixed := false
	for _, r := range res {
		give += r.Pay
		get += r.Recv
		mh := hexEncode(r.Maker)
		if maker == "" {
			maker = mh
		} else if maker != mh {
			mixed = true
		}
		// Confirm-status: a committed rung that emptied an offer is filled. The
		// Reserve already set the status; this is belt-and-suspenders for the case
		// where a release later re-opened it and a fresh commit lands.
		if f := s.fills[r.OfferID]; f != nil {
			if f.remGet == 0 || f.remGve == 0 {
				f.status = StatusFilled
			} else if f.remGet < f.get || f.remGve < f.give {
				f.status = StatusPartial
			}
		}
	}
	if mixed {
		maker = "" // multiple makers in one taker fill — no single maker
	}
	tr := Trade{
		Pair:    giveAsset + "/" + getAsset,
		Price:   ratioString(get, give),
		Give:    give,
		Get:     get,
		Maker:   maker,
		Taker:   takerPub,
		SwapKey: swapKey,
		Time:    time.Now().Unix(),
	}
	s.trades = append(s.trades, tr)
	if len(s.trades) > tradeTapeCap {
		s.trades = s.trades[len(s.trades)-tradeTapeCap:]
	}
	return tr
}

// hexEncode renders bytes as lowercase hex without importing encoding/hex here
// (keeps this file's import set minimal; the bytes are short maker pubkeys).
func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	if len(b) == 0 {
		return ""
	}
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}

// ---- trade tape queries -----------------------------------------------------

// Trades returns up to `limit` most-recent trades for `pair` (taker-orientation
// "GIVE/GET"), newest first. An empty pair returns trades across ALL pairs. A
// limit <= 0 returns all (up to the tape cap).
func (b *Book) Trades(pair string, limit int) []Trade {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sc()
	out := make([]Trade, 0, len(s.trades))
	for i := len(s.trades) - 1; i >= 0; i-- {
		t := s.trades[i]
		if pair != "" && t.Pair != pair {
			continue
		}
		out = append(out, t)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// LastPrice returns the most-recent trade price (raw atomic get/give string) for
// pair, and ok=false when the pair has no trades.
func (b *Book) LastPrice(pair string) (price string, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sc()
	for i := len(s.trades) - 1; i >= 0; i-- {
		if s.trades[i].Pair == pair {
			return s.trades[i].Price, true
		}
	}
	return "", false
}

// ---- OHLC + 24h stats -------------------------------------------------------

// Candle is one OHLCV bucket. Open/High/Low/Close are raw atomic get/give rate
// strings (the same convention as Trade.Price); Volume is Σ give over the bucket.
type Candle struct {
	OpenTime int64  `json:"open_time"` // unix seconds, bucket start
	Open     string `json:"open"`
	High     string `json:"high"`
	Low      string `json:"low"`
	Close    string `json:"close"`
	Volume   uint64 `json:"volume"` // Σ give (giveAsset) over the bucket
	Trades   int    `json:"trades"`
}

// Candles aggregates the tape for `pair` into OHLCV buckets of intervalSec each,
// returning up to `limit` most-recent buckets oldest-first. Buckets with no trade
// are omitted (sparse). Rates compare via the exact 128-bit cmpRate so OHLC is
// rounding-stable; the string form is for transport only.
func (b *Book) Candles(pair string, intervalSec int64, limit int) []Candle {
	if intervalSec <= 0 {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sc()

	// bucketAgg accumulates one interval; rates held as (num,den) for exact compare.
	type bucketAgg struct {
		start          int64
		openN, openD   uint64
		highN, highD   uint64
		lowN, lowD     uint64
		closeN, closeD uint64
		seen           bool
		vol            uint64
		count          int
	}
	byStart := map[int64]*bucketAgg{}
	var order []int64
	for _, t := range s.trades {
		if t.Pair != pair {
			continue
		}
		n, d := t.Get, t.Give
		if d == 0 {
			continue
		}
		start := (t.Time / intervalSec) * intervalSec
		bk := byStart[start]
		if bk == nil {
			bk = &bucketAgg{start: start, openN: n, openD: d, highN: n, highD: d, lowN: n, lowD: d}
			byStart[start] = bk
			order = append(order, start)
		}
		// trades replay in append (chronological) order, so close is the last seen.
		bk.closeN, bk.closeD = n, d
		bk.seen = true
		if cmpRate(n, d, bk.highN, bk.highD) > 0 {
			bk.highN, bk.highD = n, d
		}
		if cmpRate(n, d, bk.lowN, bk.lowD) < 0 {
			bk.lowN, bk.lowD = n, d
		}
		bk.vol += t.Give
		bk.count++
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	if limit > 0 && len(order) > limit {
		order = order[len(order)-limit:]
	}
	out := make([]Candle, 0, len(order))
	for _, st := range order {
		bk := byStart[st]
		out = append(out, Candle{
			OpenTime: bk.start,
			Open:     ratioString(bk.openN, bk.openD),
			High:     ratioString(bk.highN, bk.highD),
			Low:      ratioString(bk.lowN, bk.lowD),
			Close:    ratioString(bk.closeN, bk.closeD),
			Volume:   bk.vol,
			Trades:   bk.count,
		})
	}
	return out
}

// Stats24h is the rolling-24h summary for one pair derived from the tape.
type Stats24h struct {
	Pair      string `json:"pair"`
	Volume    uint64 `json:"volume"`     // Σ give over the window
	VolumeGet uint64 `json:"volume_get"` // Σ get over the window
	High      string `json:"high"`       // raw atomic get/give
	Low       string `json:"low"`
	Open      string `json:"open"`   // first trade in the window
	Last      string `json:"last"`   // most-recent trade (overall, not windowed)
	Change    string `json:"change"` // (last-open)/open as a signed decimal-ish string
	Trades    int    `json:"trades"`
}

// Stats24h computes the trailing-24h OHLC + volume for `pair` ending at now.
func (b *Book) Stats24h(pair string) Stats24h {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sc()
	out := Stats24h{Pair: pair}
	cut := time.Now().Add(-24 * time.Hour).Unix()
	var (
		highN, highD uint64
		lowN, lowD   uint64
		openN, openD uint64
		lastN, lastD uint64
		haveWindow   bool
		haveLast     bool
	)
	for _, t := range s.trades {
		if t.Pair != pair || t.Give == 0 {
			continue
		}
		// overall last (for the Last field) — trades are chronological.
		lastN, lastD = t.Get, t.Give
		haveLast = true
		if t.Time < cut {
			continue
		}
		n, d := t.Get, t.Give
		if !haveWindow {
			openN, openD = n, d
			highN, highD = n, d
			lowN, lowD = n, d
			haveWindow = true
		}
		if cmpRate(n, d, highN, highD) > 0 {
			highN, highD = n, d
		}
		if cmpRate(n, d, lowN, lowD) < 0 {
			lowN, lowD = n, d
		}
		out.Volume += t.Give
		out.VolumeGet += t.Get
		out.Trades++
	}
	if haveWindow {
		out.High = ratioString(highN, highD)
		out.Low = ratioString(lowN, lowD)
		out.Open = ratioString(openN, openD)
		// change% = (last/open - 1) as raw num/den vs open num/den. Render as a
		// signed ratio-of-ratios string for the UI; exact via cross-multiply sign.
		out.Change = changeString(openN, openD, lastN, lastD)
	}
	if haveLast {
		out.Last = ratioString(lastN, lastD)
	}
	return out
}

// changeString renders ((last/open) - 1) as a decimal-ish string. last/open =
// (lastN*openD)/(lastD*openN). We compute the signed fractional change with the
// exact 128-bit primitives, then format via ratioString with a leading sign.
func changeString(openN, openD, lastN, lastD uint64) string {
	if openN == 0 || openD == 0 || lastD == 0 {
		return "0"
	}
	// last/open numerator = lastN*openD ; denominator = lastD*openN (both 128-bit).
	// change = (lastN*openD - lastD*openN) / (lastD*openN). Keep it simple and
	// exact-enough for a UI badge: fall back to float-free ratio of the deltas via
	// 128-bit compare for sign, then a bounded ratioString of |delta|/den using
	// 64-bit reductions where they fit.
	cmp := cmpRate(lastN, lastD, openN, openD) // sign of (last - open)
	if cmp == 0 {
		return "0"
	}
	// Reduce to 64-bit-safe operands by gcd; if products still overflow we degrade
	// to "0" rather than emit a wrong value (the UI treats missing change as flat).
	num, den, okv := changeRatio(openN, openD, lastN, lastD)
	if !okv {
		if cmp > 0 {
			return "+"
		}
		return "-"
	}
	s := ratioString(num, den)
	if cmp > 0 {
		return "+" + s
	}
	return "-" + s
}

// changeRatio returns |last/open - 1| as num/den in 64-bit terms when the cross
// products fit; ok=false if they overflow (caller degrades gracefully). It uses
// gcd reduction to keep operands small.
func changeRatio(openN, openD, lastN, lastD uint64) (num, den uint64, ok bool) {
	// numerator = |lastN*openD - lastD*openN|, denominator = lastD*openN, but we
	// want the magnitude, so use absolute difference of the two cross products.
	lh, ll := mul64(lastN, openD)
	rh, rl := mul64(lastD, openN)
	// only proceed if both products fit in 64 bits (hi == 0) — common in tests.
	if lh != 0 || rh != 0 {
		return 0, 0, false
	}
	var diff uint64
	if ll >= rl {
		diff = ll - rl
	} else {
		diff = rl - ll
	}
	den = rl // lastD*openN
	if den == 0 {
		return 0, 0, false
	}
	g := gcd(diff, den)
	if g > 1 {
		diff /= g
		den /= g
	}
	return diff, den, true
}

func gcd(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}
