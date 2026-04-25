package client

import (
	"log/slog"
	"os"
)

// SetupLogging configures the global slog logger based on cfg.
func SetupLogging(cfg *Config) {
	var level slog.Level
	switch cfg.Logging.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if cfg.Logging.Format == "text" {
		handler = slog.NewTextHandler(logWriter(cfg.Logging.File), opts)
	} else {
		handler = slog.NewJSONHandler(logWriter(cfg.Logging.File), opts)
	}
	slog.SetDefault(slog.New(handler))
}

func logWriter(file string) *os.File {
	if file == "" {
		return os.Stdout
	}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		slog.Warn("cannot open log file, falling back to stdout", "file", file, "error", err)
		return os.Stdout
	}
	return f
}
