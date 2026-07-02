package swapbook

import (
	"errors"
	"sort"
	"time"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/blake2b"

	"obscura/pkg/commit"
)

// This file turns the order book from a passive "billboard" into a depth-aware
// quoting / matching engine and adds maker-authenticated cancellation plus
// per-maker anti-flood limits. Everything here is ADDITIVE and non-consensus:
// offers remain off-chain P2P RFQ quotes (see swapbook.go's package doc); a
// "match" here only tells a taker which makers, in which order, give the best
// realizable price — actual settlement is the atomic swap in pkg/swapsession.
//
// Orientation convention (matches Book.Best): a taker GIVES `giveAsset` and
// WANTS `getAsset`. A maker Offer fills that taker when the maker is on the
// other side, i.e. o.GiveAsset == getAsset and o.GetAsset == giveAsset. For one
// such offer the taker can pay up to o.GetAmount units of giveAsset to receive
// up to o.GiveAmount units of getAsset; the taker rate (getAsset per giveAsset)
// is o.GiveAmount/o.GetAmount and BIGGER is better for the taker.

// MaxOffersPerMaker caps how many live offers a single maker pubkey may hold in
// the book at once. This is anti-flood / fairness hardening at the book layer:
// the 12-bit offer PoW (OfferPoWBits) raises the cost of mass spam but does NOT
// bind spam to an identity, so a maker that is willing to grind PoW could still
// pad the book with many near-duplicate quotes and distort depth/VWAP. Capping
// per-maker offers blunts that. LIMIT: a sybil attacker with many fresh keypairs
// can still post MaxOffersPerMaker offers PER key — defeating that requires
// scarce identity (stake/consensus), which is out of scope for an off-chain RFQ
// board. We bound what we can and defer the rest to PoW + consensus.
const MaxOffersPerMaker = 64

// Quote walks the live offers that can fill a taker who gives `giveAsize` units
// of giveAsset and wants getAsset, best taker-rate first, accumulating until
// giveSize is consumed or the book side is exhausted. It returns:
//
//	filled     — units of giveAsset actually fillable (<= giveSize)
//	getOut     — total units of getAsset the taker receives for `filled`
//	vwap       — volume-weighted execution rate (getOut/filled, 0 if filled==0)
//	offersUsed — how many distinct offers were consumed (incl. the partial one)
//	full       — true iff filled == giveSize (book deep enough); false on a
//	             partial fill (book too thin)
//
// This is the depth-aware price a taker would actually receive, as opposed to
// Best() which only reports the single top-of-book rate. Each offer is consumed
// proportionally: from an offer with rate o.GiveAmount/o.GetAmount, paying `pay`
// units of giveAsset yields floor(pay * o.GiveAmount / o.GetAmount) units of
// getAsset (floor — never over-credit the taker). Determinism: offers are
// ordered by (rate desc, ID asc) so equal-rate offers tie-break stably.
func (b *Book) Quote(giveAsset, getAsset string, giveSize uint64) (filled, getOut uint64, vwap float64, offersUsed int, full bool) {
	if giveSize == 0 || !validAsset(giveAsset) || !validAsset(getAsset) || giveAsset == getAsset {
		return 0, 0, 0, 0, false
	}
	side := b.matchingOffers(giveAsset, getAsset)
	remaining := giveSize
	for _, o := range side {
		if remaining == 0 {
			break
		}
		// How much giveAsset this offer can absorb is its GetAmount; the taker
		// pays at most that for the offer's full GiveAmount.
		pay := o.GetAmount
		if pay > remaining {
			pay = remaining
		}
		if pay == 0 {
			continue
		}
		// floor(pay * GiveAmount / GetAmount) using 128-bit-safe math via
		// big-free path: GiveAmount/GetAmount are uint64; pay*GiveAmount can
		// overflow, so compute with mulDivFloor.
		got := mulDivFloor(pay, o.GiveAmount, o.GetAmount)
		if got == 0 {
			// Rate so unfavorable (or pay so small) the taker would receive 0;
			// don't spend giveAsset for nothing. Skip this offer's contribution.
			continue
		}
		filled += pay
		getOut += got
		remaining -= pay
		offersUsed++
	}
	if filled > 0 {
		vwap = float64(getOut) / float64(filled)
	}
	full = filled == giveSize
	return filled, getOut, vwap, offersUsed, full
}

// DepthLevel is one rung of the cumulative depth ladder for a pair.
type DepthLevel struct {
	Rate    float64 // taker rate at this offer (getAsset per giveAsset)
	Give    uint64  // this offer's giveAsset capacity (the maker's GetAmount)
	Get     uint64  // this offer's getAsset size  (the maker's GiveAmount)
	CumGive uint64  // cumulative giveAsset capacity through this rung
	CumGet  uint64  // cumulative getAsset through this rung
	OfferID [32]byte
}

// Depth returns the cumulative (rate, cumGive, cumGet) ladder for a taker giving
// giveAsset to receive getAsset, sorted best-rate-first (then by ID for stable
// ordering). Intended for UI / pre-trade quoting; pure read, no mutation beyond
// the opportunistic expiry prune done by the snapshot.
func (b *Book) Depth(giveAsset, getAsset string) []DepthLevel {
	if !validAsset(giveAsset) || !validAsset(getAsset) || giveAsset == getAsset {
		return nil
	}
	side := b.matchingOffers(giveAsset, getAsset)
	out := make([]DepthLevel, 0, len(side))
	var cumGive, cumGet uint64
	for _, o := range side {
		cumGive += o.GetAmount
		cumGet += o.GiveAmount
		out = append(out, DepthLevel{
			Rate:    float64(o.GiveAmount) / float64(o.GetAmount),
			Give:    o.GetAmount,
			Get:     o.GiveAmount,
			CumGive: cumGive,
			CumGet:  cumGet,
			OfferID: o.ID(),
		})
	}
	return out
}

// matchingOffers returns live offers that can fill a taker giving giveAsset for
// getAsset, sorted best-taker-rate-first with an ID tie-break for determinism.
// It uses List() (which prunes expired offers), so expired offers never appear.
func (b *Book) matchingOffers(giveAsset, getAsset string) []*Offer {
	all := b.List()
	side := make([]*Offer, 0, len(all))
	for _, o := range all {
		// Maker is the counterparty: maker gives what taker wants, wants what
		// taker gives.
		if o.GiveAsset != getAsset || o.GetAsset != giveAsset {
			continue
		}
		if o.GiveAmount == 0 || o.GetAmount == 0 {
			continue // defensive; Verify already rejects these on Add
		}
		side = append(side, o)
	}
	sort.Slice(side, func(i, j int) bool {
		// Higher taker rate (GiveAmount/GetAmount) first. Compare via cross-
		// multiplication to avoid float rounding: a.Give/a.Get > b.Give/b.Get
		// iff a.Give*b.Get > b.Give*a.Get. Use mulHiLo-free big.Int-free
		// 128-bit compare.
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

// mulDivFloor returns floor(a*b/c) without overflowing on a*b, using 64x64->128
// then 128/64. c must be non-zero (callers guarantee GetAmount>0).
func mulDivFloor(a, b, c uint64) uint64 {
	hi, lo := mul64(a, b)
	q, _ := div128by64(hi, lo, c)
	return q
}

// cmpRate compares the fractions n1/d1 and n2/d2 (all uint64, d>0) without float
// rounding. Returns -1, 0, or 1. Uses 128-bit cross products.
func cmpRate(n1, d1, n2, d2 uint64) int {
	lh, ll := mul64(n1, d2)
	rh, rl := mul64(n2, d1)
	switch {
	case lh != rh:
		if lh < rh {
			return -1
		}
		return 1
	case ll != rl:
		if ll < rl {
			return -1
		}
		return 1
	default:
		return 0
	}
}

// mul64 returns the 128-bit product of two uint64s as (hi, lo).
func mul64(a, b uint64) (hi, lo uint64) {
	const mask = 0xffffffff
	a0, a1 := a&mask, a>>32
	b0, b1 := b&mask, b>>32
	lo0 := a0 * b0
	mid1 := a1 * b0
	mid2 := a0 * b1
	hiPart := a1 * b1
	carry := (lo0>>32 + mid1&mask + mid2&mask) >> 32
	lo = lo0 + (mid1 << 32) + (mid2 << 32)
	hi = hiPart + (mid1 >> 32) + (mid2 >> 32) + carry
	return hi, lo
}

// div128by64 divides the 128-bit value (hi,lo) by d, returning the quotient and
// remainder of the FULL 128-bit dividend. Implemented as restoring bit-by-bit
// long division. The quotient is assembled in (qhi:qlo); we return only qlo
// because all callers (mulDivFloor for pay<=GetAmount) have quotients that fit
// in 64 bits. The remainder accumulator r is always < d (< 2^64), and we detect
// the high bit before shifting so the shift never loses information.
func div128by64(hi, lo, d uint64) (q, r uint64) {
	if d == 0 {
		return 0, 0
	}
	var qlo uint64
	for i := 0; i < 128; i++ {
		// Capture r's top bit BEFORE shifting: the conceptual remainder is
		// (rTop:r), a 65-bit value, because r can be as large as d-1 (< 2^64)
		// and shifting left by 1 may carry out of 64 bits.
		rTop := r >> 63
		r = (r << 1) | (hi >> 63)
		hi = (hi << 1) | (lo >> 63)
		lo = lo << 1
		qlo = qlo << 1 // quotient fits in 64 bits for all callers
		// If the 65-bit (rTop:r) >= d, subtract d and set the quotient bit.
		// rTop==1 implies (rTop:r) >= 2^64 > d, so always subtract; the uint64
		// wrap of r-=d yields the correct sub-2^64 remainder (< d by invariant).
		if rTop == 1 || r >= d {
			r -= d
			qlo |= 1
		}
	}
	return qlo, r
}

// cancelDomain is the domain separator for maker-signed cancellations, so a
// cancel signature can never be confused with an offer signature (which signs
// Core()) or any other message.
const cancelDomain = "obscura/swapbook/cancel/v1"

// CancelMessage is the canonical bytes a maker signs to authorize removing their
// offer: H(domain || offerID). Hashing binds the signature to exactly this
// offer id under a unique domain, preventing cross-protocol signature reuse.
func CancelMessage(offerID [32]byte) []byte {
	h, _ := blake2b.New256(nil)
	h.Write([]byte(cancelDomain))
	h.Write(offerID[:])
	sum := h.Sum(nil)
	return sum
}

// Cancel removes the offer with the given id IF the supplied 64-byte signature
// is a valid Schnorr signature by that offer's MAKER over CancelMessage(offerID).
// This proves the canceller controls the maker key, so forged cancels (by anyone
// who merely knows the public offer id) are rejected.
//
// LIMIT: cancellation is best-effort within THIS node's book. Because offers are
// gossiped P2P, a cancelled offer may still live in peers' books until it expires
// or the cancel propagates; there is no global revocation. Makers should keep
// TTLs short. This is an inherent property of an off-chain RFQ board, not a bug.
func (b *Book) Cancel(offerID [32]byte, sig []byte) error {
	if len(sig) != 64 {
		return errors.New("swapbook: bad cancel signature length")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked()
	o, ok := b.offers[offerID]
	if !ok {
		return errors.New("swapbook: offer not found")
	}
	fullSig, err := commit.ParseFullSig(sig)
	if err != nil {
		return errors.New("swapbook: malformed cancel signature")
	}
	if !commit.VerifyFull(o.Maker, CancelMessage(offerID), fullSig) {
		return errors.New("swapbook: cancel signature does not match maker")
	}
	delete(b.offers, offerID)
	return nil
}

// SignCancel produces the maker's authorization to cancel offerID. Helper for
// makers (and tests): signs CancelMessage(offerID) under the maker secret with
// the same Schnorr scheme Offer.Sign uses, so Cancel will accept it.
func SignCancel(makerSecret *edwards25519.Scalar, offerID [32]byte) []byte {
	return commit.Sign(makerSecret, CancelMessage(offerID)).Serialize()
}

// PruneExpired drops every offer whose Expiry is at or before `now` and returns
// the number removed. Add() and the read paths already prune opportunistically
// (via pruneLocked, which uses time.Now); this exported method lets callers
// sweep with an explicit clock (useful for tests and deterministic batch sweeps)
// without spawning a background goroutine.
func (b *Book) PruneExpired(now time.Time) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	cut := now.Unix()
	n := 0
	for id, o := range b.offers {
		if o.Expiry <= cut {
			delete(b.offers, id)
			n++
		}
	}
	return n
}
