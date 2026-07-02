package swapnet

import "obscura/pkg/p2p"

// P2PTransport adapts a *p2p.Node to the Transport interface: directed swap
// envelopes go out over p2p.SendSwapSession, and inbound msgSwapSession envelopes
// are delivered to a Coordinator. Wire it up with BindP2P, which connects the
// node's OnSwapSession callback to the coordinator's Deliver.
type P2PTransport struct {
	node *p2p.Node
}

// NewP2PTransport wraps a p2p node as a swap transport.
func NewP2PTransport(node *p2p.Node) *P2PTransport { return &P2PTransport{node: node} }

// Send ships one directed envelope to the peer at peerAddr over p2p.
func (t *P2PTransport) Send(peerAddr string, env *Envelope) error {
	return t.node.SendSwapSession(peerAddr, env.Serialize())
}

// ResolvePeer implements PeerResolver: re-resolve a counterparty's live handle when
// its connection dropped + reconnected under a new ephemeral port (see
// p2p.SwapPeerForHost). Lets the coordinator's send survive a mid-swap reconnect.
func (t *P2PTransport) ResolvePeer(stale string) (string, bool) {
	return t.node.SwapPeerForHost(stale)
}

// BindInbound routes a node's inbound directed swap envelopes into coord. Call it
// after constructing the coordinator (the transport itself only needs the node, so
// build it with NewP2PTransport first, pass to swapnet.New, then call BindInbound).
// Order:
//
//	tr := swapnet.NewP2PTransport(node)
//	coord, _ := swapnet.New(swapnet.Config{Transport: tr, ...})
//	tr.BindInbound(coord)
func (t *P2PTransport) BindInbound(coord *Coordinator) {
	t.node.OnSwapSession = func(fromPeer string, payload []byte) {
		coord.Deliver(fromPeer, payload)
	}
}
