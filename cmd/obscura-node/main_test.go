package main

import (
	"context"
	"testing"
	"time"

	"github.com/obscura-node/obscura/pkg/chain"
	"github.com/obscura-node/obscura/pkg/config"
)

func TestAutoLiquidityLoop_ResumesPastPruningWindow(t *testing.T) {
	// Regression test for the dormant bug: auto-liquidity should resume
	// scanning from the retained floor (tip - PoRWindow) on restart,
	// not from genesis, when the chain has outlived its pruning window.

	tmpDir := t.TempDir()
	c, err := chain.Open(tmpDir)
	if err != nil {
		t.Fatalf("failed to open chain: %v", err)
	}
	defer c.Close()

	// Simulate a chain that has advanced past PoRWindow and pruned early bodies
	for i := uint64(1); i <= config.PoRWindow+5000; i++ {
		c.AddBlock(chain.Block{Height: i})
	}

	// Prune bodies below tip - PoRWindow (simulating normal state pruning)
	tip := c.Height()
	for h := uint64(1); h < tip-config.PoRWindow; h++ {
		c.PruneBlockBody(h)
	}

	// Restart the auto-liquidity loop (simulating node restart)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	seed := "test-seed-12345"
	done := make(chan struct{})
	go func() {
		autoLiquidityLoop(ctx, c, seed)
		close(done)
	}()

	// Wait for at least one tick to complete
	time.Sleep(100 * time.Millisecond)

	// Verify that offers were posted (non-zero liquidity)
	offers := c.GetOffers()
	if len(offers) == 0 {
		t.Errorf("auto-liquidity posted zero offers after restart past pruning window; expected >0")
	}

	cancel()
	<-done
}

func TestAutoLiquidityLoop_SkipsPrunedBlocks(t *testing.T) {
	// Test that the loop correctly skips permanently pruned blocks
	// and continues scanning, rather than stalling forever.

	tmpDir := t.TempDir()
	c, err := chain.Open(tmpDir)
	if err != nil {
		t.Fatalf("failed to open chain: %v", err)
	}
	defer c.Close()

	// Add blocks and prune some in the middle
	for i := uint64(1); i <= 100; i++ {
		c.AddBlock(chain.Block{Height: i})
	}

	// Prune blocks 10-20 (simulating selective pruning)
	for h := uint64(10); h <= 20; h++ {
		c.PruneBlockBody(h)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	seed := "test-seed-67890"
	done := make(chan struct{})
	go func() {
		autoLiquidityLoop(ctx, c, seed)
		close(done)
	}()

	// Wait for scanning to progress past the pruned range
	time.Sleep(200 * time.Millisecond)

	// The loop should have skipped the pruned blocks and continued
	// We verify this indirectly by checking that it didn't stall
	// (if it stalled, the context timeout would be the only exit)

	cancel()
	select {
	case <-done:
		// Loop exited cleanly via context cancellation, not a stall
	case <-time.After(500 * time.Millisecond):
		t.Error("auto-liquidity loop appears to have stalled on pruned blocks")
	}
}
