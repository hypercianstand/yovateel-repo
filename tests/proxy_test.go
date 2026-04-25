package tests

import (
	"context"
	"testing"

	"github.com/sartoopjj/vpn-over-github/shared"
	"github.com/sartoopjj/vpn-over-github/tests/mocks"
)

func TestMockTransportListChannels(t *testing.T) {
	ctx := context.Background()
	tr := mocks.NewMockTransport()
	ch1, err := tr.EnsureChannel(ctx, "")
	if err != nil {
		t.Fatalf("EnsureChannel(1): %v", err)
	}
	_, err = tr.EnsureChannel(ctx, "")
	if err != nil {
		t.Fatalf("EnsureChannel(2): %v", err)
	}

	channels, err := tr.ListChannels(ctx)
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}
	if len(channels) != 2 {
		t.Fatalf("expected 2 channels, got %d", len(channels))
	}
	if channels[0].ID != ch1 {
		t.Fatalf("expected first channel ID %q, got %q", ch1, channels[0].ID)
	}
}

func TestMockTransportDeleteChannelIdempotent(t *testing.T) {
	ctx := context.Background()
	tr := mocks.NewMockTransport()
	ch, err := tr.EnsureChannel(ctx, "")
	if err != nil {
		t.Fatalf("EnsureChannel: %v", err)
	}
	if err := tr.DeleteChannel(ctx, ch); err != nil {
		t.Fatalf("DeleteChannel first call: %v", err)
	}
	if err := tr.DeleteChannel(ctx, ch); err != nil {
		t.Fatalf("DeleteChannel second call should be idempotent: %v", err)
	}
	_, err = tr.Read(ctx, ch, shared.ClientBatchFile)
	if err == nil {
		t.Fatal("expected read after delete to fail")
	}
}
