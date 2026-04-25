package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/sartoopjj/vpn-over-github/shared"
)

// CleanupDaemon periodically deletes stale upstream channels.
type CleanupDaemon struct {
	cfg        *ServerConfig
	transports map[int]shared.Transport
}

func NewCleanupDaemon(cfg *ServerConfig, transports map[int]shared.Transport) *CleanupDaemon {
	return &CleanupDaemon{cfg: cfg, transports: transports}
}

func (d *CleanupDaemon) Run(ctx context.Context) {
	d.cleanup(ctx)
	ticker := time.NewTicker(d.cfg.Cleanup.Interval)
	defer ticker.Stop()

	slog.Info("cleanup daemon started", "interval", d.cfg.Cleanup.Interval.String(), "ttl", d.cfg.Cleanup.DeadConnectionTTL.String())
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.cleanup(ctx)
		}
	}
}

func (d *CleanupDaemon) cleanup(ctx context.Context) {
	now := time.Now()
	deleted := 0
	for tokenIdx, transport := range d.transports {
		channels, err := transport.ListChannels(ctx)
		if err != nil {
			slog.Warn("cleanup list channels failed", "token_index", tokenIdx, "error", err)
			continue
		}
		for _, ch := range channels {
			if now.Sub(ch.UpdatedAt) <= d.cfg.Cleanup.DeadConnectionTTL {
				continue
			}

			batch, err := transport.Read(ctx, ch.ID, shared.ClientBatchFile)
			if err != nil {
				slog.Debug("cleanup read client batch failed", "channel_id", ch.ID, "error", err)
				continue
			}
			if batch != nil && batch.Ts > 0 {
				last := time.Unix(batch.Ts, 0)
				if now.Sub(last) <= d.cfg.Cleanup.DeadConnectionTTL {
					continue
				}
			}

			if err := transport.DeleteChannel(ctx, ch.ID); err != nil {
				slog.Warn("cleanup delete channel failed", "channel_id", ch.ID, "error", err)
				continue
			}
			deleted++
		}
	}
	if deleted > 0 {
		slog.Info("cleanup deleted channels", "count", deleted)
	}
}
