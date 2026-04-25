package client

import (
	"time"

	"github.com/sartoopjj/vpn-over-github/shared"
)

// ConnSnapshot is a point-in-time view of an active tunnel connection.
type ConnSnapshot struct {
	ConnID    string
	Dst       string
	Transport string
	TokenIdx  int
	BytesUp   int64
	BytesDown int64
	StartTime time.Time
}

// TokenSnapshot is a point-in-time view of a GitHub token's rate-limit state.
type TokenSnapshot struct {
	MaskedToken   string
	Transport     string
	Remaining     int
	Total         int
	BackoffUntil  time.Time
	WritesPerMin  int
	WritesPerHour int
	TotalAPICalls int64
}

// RateSnapshot returns a point-in-time view of all token rate-limit states.
func (r *RateLimiter) RateSnapshot(totalPerToken int, tokens []TokenConfig) []TokenSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]TokenSnapshot, len(r.states))
	for i, s := range r.states {
		total := totalPerToken
		if s.RateLimitTotal > 0 {
			total = s.RateLimitTotal
		}
		transport := ""
		if i < len(tokens) {
			transport = tokens[i].Transport
		}
		if transport == "" {
			transport = "git"
		}
		out[i] = TokenSnapshot{
			MaskedToken:   shared.MaskToken(s.Token),
			Transport:     transport,
			Remaining:     s.RateLimitRemaining,
			Total:         total,
			BackoffUntil:  s.BackoffUntil,
			WritesPerMin:  s.WritesThisMinute,
			WritesPerHour: s.WritesThisHour,
			TotalAPICalls: s.TotalAPICalls,
		}
	}
	return out
}
