package swapbook

import (
	"time"

	"filippo.io/edwards25519"
)

// This file contains the SERVER-SIDE offer constructor used by a mining node's
// auto-liquidity loop (cmd/obscura-node). It replicates EXACTLY the construction
// the web wallet's WASM does (obxBuildOffer): build an Offer, then o.Sign(secret)
// — which grinds the anti-spam PoW and Schnorr-signs Core(). Keeping it here lets
// the node build admissible offers without duplicating the signing convention and
// lets it be unit-tested in-package. This is NON-CONSENSUS: offers are off-chain
// P2P gossip, never a chain transaction.

// BuildSignedOffer constructs and signs a swap offer giving giveAmount of giveAsset
// for getAmount of getAsset, valid for ttl, signed by makerSecret. The maker pubkey,
// PoW nonce, and signature are all set by Sign. The returned offer satisfies Verify
// (so Book.Add will admit it) as long as the asset/amount/ttl arguments are sane.
//
// The caller (the node) is responsible for the human→atomic amount conversion and
// for the maker-secret derivation (which must match the wallet's so the offers are
// attributable to the same maker identity as a manually-posted offer).
func BuildSignedOffer(giveAsset, getAsset string, giveAmount, getAmount uint64, ttl time.Duration, makerSecret *edwards25519.Scalar) *Offer {
	if ttl <= 0 || ttl > MaxOfferTTL {
		ttl = MaxOfferTTL
	}
	o := &Offer{
		GiveAsset:  giveAsset,
		GetAsset:   getAsset,
		GiveAmount: giveAmount,
		GetAmount:  getAmount,
		Expiry:     time.Now().Add(ttl).Unix(),
	}
	o.Sign(makerSecret)
	return o
}

// MakerOffers returns the live offers in the book made by the given maker pubkey
// (32-byte ed25519). The auto-liquidity loop uses this to count its own outstanding
// auto-offers so it can cap them and avoid re-posting on every tick.
func (b *Book) MakerOffers(maker []byte) []*Offer {
	if len(maker) != 32 {
		return nil
	}
	all := b.List()
	out := make([]*Offer, 0, len(all))
	for _, o := range all {
		if len(o.Maker) == 32 && string(o.Maker) == string(maker) {
			out = append(out, o)
		}
	}
	return out
}
