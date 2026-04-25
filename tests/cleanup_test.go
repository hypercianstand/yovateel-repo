package tests

import (
	"context"
	"testing"
	"time"

	"github.com/sartoopjj/vpn-over-github/server"
	"github.com/sartoopjj/vpn-over-github/shared"
	"github.com/sartoopjj/vpn-over-github/tests/mocks"
)

func TestCleanupDeletesStaleChannel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tr := mocks.NewMockTransport()
	ch, err := tr.EnsureChannel(ctx, "")
	if err != nil {
		t.Fatalf("EnsureChannel: %v", err)
	}
	if err := tr.SetUpdatedAt(ch, time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatalf("SetUpdatedAt: %v", err)
	}

	cfg := server.DefaultServerConfig()
	cfg.Cleanup.Enabled = true
	cfg.Cleanup.Interval = 10 * time.Millisecond
	cfg.Cleanup.DeadConnectionTTL = 1 * time.Second

	d := server.NewCleanupDaemon(cfg, map[int]shared.Transport{0: tr})
	go d.Run(ctx)
	time.Sleep(60 * time.Millisecond)
	cancel()

	channels, err := tr.ListChannels(context.Background())
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}
	if len(channels) != 0 {
		t.Fatalf("expected stale channel to be deleted, remaining=%d", len(channels))
	}
}
