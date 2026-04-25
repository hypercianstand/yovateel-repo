package server

import (
	"log/slog"
	"os"
)

// SetupLogging configures the global slog logger based on cfg.
func SetupLogging(cfg *ServerConfig) {
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
	out := serverLogWriter(cfg.Logging.File)
	if cfg.Logging.Format == "text" {
		handler = slog.NewTextHandler(out, opts)
	} else {
		handler = slog.NewJSONHandler(out, opts)
	}
	slog.SetDefault(slog.New(handler))
}

func serverLogWriter(file string) *os.File {
	if file == "" {
		return os.Stdout
	}
	if err := os.MkdirAll(getDir(file), 0o755); err != nil {
		return os.Stdout
	}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return os.Stdout
	}
	return f
}

func getDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
