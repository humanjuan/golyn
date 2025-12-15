package lifecycle

import (
	"context"
	"sync"

	"github.com/humanjuan/golyn/globals"
)

type Hook interface {
	OnStart(ctx context.Context) error
	OnShutdown(ctx context.Context) error
}

var (
	hooks []Hook
	mu    sync.Mutex
)

// Register registers a lifecycle hook.
// Order matters: hooks are started in registration order
// and shutdown in reverse order.
func Register(h Hook) {
	mu.Lock()
	defer mu.Unlock()

	hooks = append(hooks, h)

	if log := globals.GetAppLogger(); log != nil {
		log.Info(
			"lifecycle | hook registered | total=%d | type=%T",
			len(hooks),
			h,
		)
	}
}

// Start executes all registered hooks in order.
func Start(ctx context.Context) error {
	if log := globals.GetAppLogger(); log != nil {
		log.Info(
			"lifecycle | starting | hooks=%d",
			len(hooks),
		)
	}

	for i, h := range hooks {
		if log := globals.GetAppLogger(); log != nil {
			log.Debug(
				"lifecycle | starting hook | index=%d | type=%T",
				i+1,
				h,
			)
		}

		if err := h.OnStart(ctx); err != nil {
			if log := globals.GetAppLogger(); log != nil {
				log.Error(
					"lifecycle | hook start failed | index=%d | type=%T | error=%v",
					i+1,
					h,
					err,
				)
			}
			return err
		}
	}

	if log := globals.GetAppLogger(); log != nil {
		log.Info("lifecycle | all hooks started")
	}

	return nil
}

// Shutdown executes all hooks in reverse order.
func Shutdown(ctx context.Context) {
	if log := globals.GetAppLogger(); log != nil {
		log.Info(
			"lifecycle | shutting down | hooks=%d",
			len(hooks),
		)
	}

	for i := len(hooks) - 1; i >= 0; i-- {
		h := hooks[i]

		if log := globals.GetAppLogger(); log != nil {
			log.Debug(
				"lifecycle | shutting down hook | index=%d | type=%T",
				i+1,
				h,
			)
		}

		if err := h.OnShutdown(ctx); err != nil {
			if log := globals.GetAppLogger(); log != nil {
				log.Error(
					"lifecycle | hook shutdown failed | index=%d | type=%T | error=%v",
					i+1,
					h,
					err,
				)
			}
		}
	}

	if log := globals.GetAppLogger(); log != nil {
		log.Info("lifecycle | shutdown complete")
	}
}
