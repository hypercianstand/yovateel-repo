package client

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/sartoopjj/vpn-over-github/shared"
)

// RateLimiter manages per-token rate limit state and enforces client-side
// throttling before hitting GitHub's actual rate limits.
type RateLimiter struct {
	mu           sync.Mutex
	states       []*shared.TokenState
	cfg          *Config
	nextTokenIdx int
}

// NewRateLimiter creates a RateLimiter for the given list of tokens.
func NewRateLimiter(tokens []string, cfg *Config) *RateLimiter {
	states := make([]*shared.TokenState, len(tokens))
	for i, tok := range tokens {
		states[i] = &shared.TokenState{
			Token:              tok,
			RateLimitRemaining: cfg.RateLimit.MaxRequestsPerHour,
			Priority:           1,
		}
	}
	return &RateLimiter{
		states: states,
		cfg:    cfg,
	}
}

func (r *RateLimiter) Acquire(ctx context.Context, tokenIdx int) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		r.mu.Lock()
		state := r.states[tokenIdx]
		wait := r.checkAndUpdateState(state)
		r.mu.Unlock()

		if wait == 0 {
			return nil
		}

		slog.Debug("rate limiter backoff",
			"token", shared.MaskToken(r.states[tokenIdx].Token),
			"wait_ms", wait.Milliseconds(),
		)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (r *RateLimiter) checkAndUpdateState(state *shared.TokenState) time.Duration {
	now := time.Now()

	if now.Before(state.BackoffUntil) {
		return time.Until(state.BackoffUntil)
	}

	if now.Sub(state.LastSecondStart) >= time.Second {
		state.LastSecondStart = now
		state.RequestsThisSecond = 0
	}
	if state.RequestsThisSecond >= r.cfg.RateLimit.BurstLimit {
		nextSecond := state.LastSecondStart.Add(time.Second)
		return time.Until(nextSecond)
	}

	warningLevel := r.cfg.RateLimit.LowRemainingWarn
	if state.RateLimitRemaining <= warningLevel && state.RateLimitRemaining > 0 {
		fraction := float64(warningLevel-state.RateLimitRemaining) / float64(warningLevel)
		_ = fraction
		backoffSec := math.Pow(float64(r.cfg.RateLimit.BackoffMultiplier), float64(state.BackoffLevel)) - 1
		if backoffSec > 0 {
			state.BackoffLevel = min(state.BackoffLevel+1, 6)
			backoffDur := time.Duration(backoffSec * float64(time.Second))
			state.BackoffUntil = now.Add(backoffDur)
			slog.Warn("approaching rate limit, backing off",
				"token", shared.MaskToken(state.Token),
				"remaining", state.RateLimitRemaining,
				"backoff_sec", backoffSec,
			)
			return backoffDur
		}
	}

	state.RequestsThisSecond++
	if state.RateLimitRemaining > 0 {
		state.RateLimitRemaining--
	}

	return 0
}

func (r *RateLimiter) UpdateFromHeaders(tokenIdx int, info shared.RateLimitInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if tokenIdx < 0 || tokenIdx >= len(r.states) {
		return
	}

	state := r.states[tokenIdx]
	now := time.Now()

	// Skip git transport sentinel (Limit=99999) and stale info.
	if info.LastUpdated.After(now.Add(-5*time.Second)) && info.Limit < 99999 {
		prevRemaining := state.RateLimitRemaining
		state.RateLimitRemaining = info.Remaining
		state.RateLimitReset = info.ResetAt
		if info.Limit > 0 {
			state.RateLimitTotal = info.Limit
		}

		if !info.RetryAfter.IsZero() && info.RetryAfter.After(state.BackoffUntil) {
			state.BackoffUntil = info.RetryAfter
		}

		if info.Remaining > prevRemaining {
			state.BackoffLevel = 0
			state.BackoffUntil = time.Time{}
		}

		threshold := r.cfg.RateLimit.LowRemainingWarn
		if info.Remaining <= threshold {
			slog.Warn("rate limit approaching warning threshold",
				"token", shared.MaskToken(state.Token),
				"remaining", info.Remaining,
				"threshold", threshold,
				"reset_at", info.ResetAt.Format(time.RFC3339),
			)
		}
	}
}

// GetBestToken selects the best available token using round-robin, skipping tokens in backoff.
func (r *RateLimiter) GetBestToken() (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	n := len(r.states)
	now := time.Now()

	for i := 0; i < n; i++ {
		idx := (r.nextTokenIdx + i) % n
		state := r.states[idx]
		if state.BackoffUntil.IsZero() || now.After(state.BackoffUntil) {
			r.nextTokenIdx = (idx + 1) % n
			return idx, nil
		}
	}

	earliest := r.states[0].BackoffUntil
	for _, s := range r.states[1:] {
		if s.BackoffUntil.Before(earliest) {
			earliest = s.BackoffUntil
		}
	}

	return 0, fmt.Errorf("all %d tokens are rate-limited by GitHub; earliest recovery at %s",
		n, earliest.Format(time.RFC3339))
}

// MarkRateLimited immediately backs off the specified token after a primary
// rate-limit 403/429 response (x-ratelimit-remaining = 0).
func (r *RateLimiter) MarkRateLimited(tokenIdx int, resetAt time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if tokenIdx < 0 || tokenIdx >= len(r.states) {
		return
	}

	state := r.states[tokenIdx]
	state.RateLimitRemaining = 0
	state.RateLimitReset = resetAt
	state.BackoffUntil = resetAt
	state.BackoffLevel = 0

	slog.Warn("token primary rate-limited by GitHub; backing off until reset",
		"token", shared.MaskToken(state.Token),
		"reset_at", resetAt.Format(time.RFC3339),
	)
}

// MarkSecondaryRateLimited backs off the token after a secondary rate-limit
// response. retryAfter is taken from the Retry-After header; if zero, a
// 60-second minimum is applied (GitHub recommendation).
func (r *RateLimiter) MarkSecondaryRateLimited(tokenIdx int, retryAfter time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if tokenIdx < 0 || tokenIdx >= len(r.states) {
		return
	}

	state := r.states[tokenIdx]
	backoffUntil := retryAfter
	if backoffUntil.IsZero() || time.Until(backoffUntil) < 60*time.Second {
		backoffUntil = time.Now().Add(60 * time.Second)
	}
	state.BackoffUntil = backoffUntil

	slog.Warn("token secondary rate-limited by GitHub; backing off",
		"token", shared.MaskToken(state.Token),
		"backoff_until", backoffUntil.Format(time.RFC3339),
	)
}

// RecordWrite tracks per-minute/hour write counters; returns wait duration if secondary limits hit.
func (r *RateLimiter) RecordWrite(tokenIdx int) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()

	if tokenIdx < 0 || tokenIdx >= len(r.states) {
		return 0
	}
	state := r.states[tokenIdx]
	now := time.Now()

	if now.Sub(state.WriteMinuteStart) >= time.Minute {
		state.WriteMinuteStart = now
		state.WritesThisMinute = 0
	}
	if now.Sub(state.WriteHourStart) >= time.Hour {
		state.WriteHourStart = now
		state.WritesThisHour = 0
	}

	state.WritesThisMinute++
	state.WritesThisHour++

	const maxWritesPerHour = 500
	if state.WritesThisHour >= maxWritesPerHour {
		wait := time.Until(state.WriteHourStart.Add(time.Hour))
		if wait > 0 {
			slog.Warn("approaching secondary write limit (500/hr); throttling",
				"token", shared.MaskToken(state.Token),
				"writes_this_hour", state.WritesThisHour,
				"wait", wait.Round(time.Second),
			)
			return wait
		}
	}

	const maxWritesPerMinute = 80
	if state.WritesThisMinute >= maxWritesPerMinute {
		wait := time.Until(state.WriteMinuteStart.Add(time.Minute))
		if wait > 0 {
			slog.Warn("approaching secondary write limit (80/min); throttling",
				"token", shared.MaskToken(state.Token),
				"writes_this_minute", state.WritesThisMinute,
				"wait", wait.Round(time.Second),
			)
			return wait
		}
	}

	return 0
}

// WriteCounters returns the current write-rate counters for the given token.
// Used by the TUI to show secondary rate limit progress.
func (r *RateLimiter) WriteCounters(tokenIdx int) (perMin, perHour int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if tokenIdx < 0 || tokenIdx >= len(r.states) {
		return 0, 0
	}
	return r.states[tokenIdx].WritesThisMinute, r.states[tokenIdx].WritesThisHour
}

// RecordTransportCall increments total observed transport operations for a token.
// This counter is shown in the TUI and applies to both gist and git transports.
func (r *RateLimiter) RecordTransportCall(tokenIdx int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if tokenIdx < 0 || tokenIdx >= len(r.states) {
		return
	}
	r.states[tokenIdx].TotalAPICalls++
}

// LogStatus logs the current rate limit status for all tokens at DEBUG level.
// Useful for diagnosing rate limit issues.
func (r *RateLimiter) LogStatus() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, state := range r.states {
		inBackoff := time.Now().Before(state.BackoffUntil)
		slog.Debug("token rate limit status",
			"token_index", i,
			"token", shared.MaskToken(state.Token),
			"remaining", state.RateLimitRemaining,
			"reset_at", state.RateLimitReset.Format(time.RFC3339),
			"in_backoff", inBackoff,
			"backoff_until", state.BackoffUntil.Format(time.RFC3339),
			"backoff_level", state.BackoffLevel,
		)
	}
}

// TokenCount returns the number of configured tokens.
func (r *RateLimiter) TokenCount() int {
	return len(r.states)
}

// GetToken returns the raw token string for the given index.
// Used when creating the API client for a specific token.
func (r *RateLimiter) GetToken(idx int) string {
	if idx < 0 || idx >= len(r.states) {
		return ""
	}
	return r.states[idx].Token
}

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
