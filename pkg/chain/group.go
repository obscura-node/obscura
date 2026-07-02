package chain

import (
	"fmt"

	"obscura/pkg/config"
	"obscura/pkg/group"
)

// NewConfiguredGroup builds the group of unknown order selected by config.
// All nodes must agree on this for consensus.
func NewConfiguredGroup() (group.Group, error) {
	switch config.AccumulatorBackend {
	case "rsa2048":
		return group.NewRSA2048Group(), nil
	case "classgroup":
		D := group.DeriveDiscriminant([]byte(config.NetworkSeed), config.ClassGroupDiscriminantBits)
		return group.NewClassGroup(D, "classgroup-d2048")
	default:
		return nil, fmt.Errorf("chain: unknown accumulator backend %q", config.AccumulatorBackend)
	}
}
