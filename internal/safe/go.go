package safe

import (
	"log/slog"
)

// Go runs fn in a goroutine and logs panics instead of crashing the process.
func Go(log *slog.Logger, name string, fn func()) {
	if log == nil {
		log = slog.Default()
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error("panic recovered", "where", name, "panic", r)
			}
		}()
		fn()
	}()
}
