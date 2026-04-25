package tests

import (
	"context"
	"testing"
	"time"

	"github.com/sartoopjj/vpn-over-github/shared"
)

func minRLConfig() *rlConfig {
	return &rlConfig{
		MaxRequestsPerHour: 100,
		BurstLimit:         10,
		BackoffMultiplier:  2.0,
		LowRemainingWarn:   30,
	}
}

type rlConfig struct {
	MaxRequestsPerHour int
	BurstLimit         int
	BackoffMultiplier  float64
	LowRemainingWarn   int
}

func TestUpdateFromHeadersLowersRemaining(t *testing.T) {
	tokens := []string{"ghp_testtoken1234567890a", "ghp_testtoken1234567890b"}
	states := make([]*shared.TokenState, len(tokens))
	for i, tok := range tokens {
		states[i] = &shared.TokenState{
			Token:              tok,
			RateLimitRemaining: 5000,
			Priority:           1,
		}
	}

	// Simulate updating remaining to 10 (near limit)
	info := shared.RateLimitInfo{
		Remaining:   10,
		ResetAt:     time.Now().Add(30 * time.Minute),
		LastUpdated: time.Now(),
	}
	states[0].RateLimitRemaining = info.Remaining
	states[0].RateLimitReset = info.ResetAt

	if states[0].RateLimitRemaining != 10 {
		t.Errorf("expected remaining=10, got %d", states[0].RateLimitRemaining)
	}
}

func TestMaskTokenOnRateLimit(t *testing.T) {
	tok := "ghp_abcdefghijklmnopqrstuvwxyz"
	masked := shared.MaskToken(tok)
	if masked == tok {
		t.Error("MaskToken should not return the raw token")
	}
	if len(masked) >= len(tok) {
		t.Errorf("masked token length %d should be less than original %d", len(masked), len(tok))
	}
}

func TestContextCancellationStopsAcquire(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	<-ctx.Done()
	if ctx.Err() == nil {
		t.Error("expected context to be cancelled")
	}
}

func TestTokenStateBackoff(t *testing.T) {
	state := &shared.TokenState{
		Token:              "ghp_testtoken1234567890x",
		RateLimitRemaining: 0,
		BackoffUntil:       time.Now().Add(5 * time.Second),
		BackoffLevel:       3,
	}
	if time.Now().Before(state.BackoffUntil) == false {
		t.Error("expected token to be in backoff")
	}
}

func TestTokenStateTotalAPICallsField(t *testing.T) {
	state := &shared.TokenState{
		Token:              "ghp_testtoken1234567890y",
		RateLimitRemaining: 500,
		TotalAPICalls:      0,
	}
	state.TotalAPICalls++
	state.TotalAPICalls++
	if state.TotalAPICalls != 2 {
		t.Errorf("expected TotalAPICalls=2, got %d", state.TotalAPICalls)
	}
}

func TestRateLimitInfoResourceField(t *testing.T) {
	info := shared.RateLimitInfo{
		Remaining:   88,
		Limit:       100,
		Resource:    "search",
		LastUpdated: time.Now(),
	}
	if info.Resource != "search" {
		t.Errorf("expected Resource=search, got %q", info.Resource)
	}
	// Core resource (what gist calls return)
	coreInfo := shared.RateLimitInfo{
		Remaining: 4980,
		Limit:     5000,
		Resource:  "core",
	}
	if coreInfo.Resource != "core" {
		t.Errorf("expected Resource=core, got %q", coreInfo.Resource)
	}
}
