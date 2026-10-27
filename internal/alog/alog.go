// Package alog initializes the agent's operational logger: a slog
// handler that writes to stderr and (optionally) a rotated file.
package alog

import (
	"io"
	"log/slog"
	"os"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Init returns a slog.Logger that mirrors output to stderr and, when
// path is non-empty, to a rotated file at path. When path is empty,
// only stderr is used.
func Init(path string, level slog.Level) *slog.Logger {
	var w io.Writer = os.Stderr
	if path != "" {
		rot := &lumberjack.Logger{
			Filename:   path,
			MaxSize:    100,
			MaxBackups: 5,
			MaxAge:     0,
			Compress:   false,
		}
		w = io.MultiWriter(os.Stderr, rot)
	}
	h := slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
	return slog.New(h)
}
