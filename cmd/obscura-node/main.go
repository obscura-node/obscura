package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/obscura-node/obscura/pkg/chain"
	"github.com/obscura-node/obscura/pkg/config"
	"github.com/obscura-node/obscura/pkg/wallet"
)

func main() {
	var (
		dataDir = flag.String("data", "./data", "data directory")
		seed    = flag.String("seed", "", "wallet seed for auto-liquidity")
		port    = flag.Int("port", 8080, "HTTP port")
	)
	flag.Parse()

	if *seed == "" {
		log.Fatal("--seed required for auto-liquidity")
	}

	c, err := chain.Open(*dataDir)
	if err != nil {
		log.Fatalf("failed to open chain: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go autoLiquidityLoop(ctx, c, *seed)

	http.HandleFunc("/offers/json", handleOffers(c))
	http.HandleFunc("/liquidity", handleLiquidity(c))

	srv := &http.Server{Addr: fmt.Sprintf(":%d", *port)}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("shutting down...")
	cancel()
	srv.Shutdown(context.Background())
}

func autoLiquidityLoop(ctx context.Context, c *chain.Chain, seed string) {
	w := wallet.FromSeed(seed)
	var scanned uint64

	// Start from the retained floor, not genesis, on loop startup
	if h := c.Height(); h > config.PoRWindow {
		scanned = h - config.PoRWindow
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tip := c.Height()

			// Scan new blocks to update wallet state
			for h := scanned + 1; h <= tip; h++ {
				b, ok := c.BlockByHeight(h)
				if !ok {
					// Distinguish permanently pruned from not-yet-arrived
					if tip-h > config.PoRWindow {
						// Permanently pruned — skip past it, keep going
						scanned = h
						continue
					}
					// Recent height, body just not here yet — retry next tick
					break
				}
				w.ScanBlock(b)
				scanned = h
			}

			spendable := w.SpendableOutputs()
			if spendable == 0 {
				continue
			}

			// Post competitive OBX→XNO sell offers
			offers := buildOffers(spendable)
			for _, offer := range offers {
				if err := c.PostOffer(offer); err != nil {
					log.Printf("failed to post offer: %v", err)
					continue
				}
			}
			log.Printf("auto-liquidity: posted %d competitive OBX→XNO rungs", len(offers))
		}
	}
}

func buildOffers(spendable uint64) []Offer {
	// Build 16 rungs of 5 OBX each, competitive pricing
	var offers []Offer
	for i := 0; i < 16 && spendable >= 5; i++ {
		offers = append(offers, Offer{
			Amount: 5,
			Price:  basePrice() + float64(i)*0.001,
		})
		spendable -= 5
	}
	return offers
}

func basePrice() float64 {
	return 0.01 // placeholder market rate
}

type Offer struct {
	Amount uint64
	Price  float64
}

func handleOffers(c *chain.Chain) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		offers := c.GetOffers()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"total": %d}`, len(offers))
	}
}

func handleLiquidity(c *chain.Chain) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		offers := c.GetOffers()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"offers": %d}`, len(offers))
	}
}
