package lifecycle

import (
	"context"
	"fmt"
	"sync"

	"github.com/humanjuan/golyn/globals"
)

type Hook interface {
	OnStart(ctx context.Context) error
	OnShutdown(ctx context.Context) error
}

type registeredHook struct {
	id   string
	hook Hook
}

var (
	hooks         []registeredHook
	mu            sync.Mutex
	NoExtensions  bool
	isInitialized bool
)

// RouterHook is implemented by components that want to register HTTP routes
// once the main router is ready.
// Moved to router.go

// Register registers a lifecycle hook.
// Order matters: hooks are started in registration order
// and shutdown in reverse order.
func Register(id string, secret string, h Hook) error {
	mu.Lock()
	defer mu.Unlock()

	log := globals.GetAppLogger()

	if NoExtensions {
		if log != nil {
			log.Warn("Register() | lifecycle | registration ignored due to --no-extensions flag | id=%s", id)
		}
		return nil
	}

	conf := globals.GetConfig()
	if conf != nil {
		if !conf.Extensions.Enabled {
			if log != nil {
				log.Warn("Register() | lifecycle | extensions are disabled in config | id=%s", id)
			}
			return nil
		}

		expectedSecret, ok := conf.Extensions.Whitelist[id]
		if !ok || expectedSecret != secret {
			if log != nil {
				log.Error("[CRITICAL] Unauthorized extension attempt | id=%s", id)
				log.Sync()
			}
			return fmt.Errorf("unauthorized extension: %s", id)
		}
	} else if isInitialized {
		// If we are initialized but config is nil (should not happen in production)
		return fmt.Errorf("config not loaded")
	}
	// Note: If conf is nil, and we are not initialized, we allow it for now
	// as some registers might happen in init() before LoadConfig.
	// But we will need a way to validate them later.

	hooks = append(hooks, registeredHook{id: id, hook: h})

	if log != nil {
		log.Info(
			"Register() | lifecycle | hook registered | total=%d | id=%s | type=%T",
			len(hooks),
			id,
			h,
		)
	}
	return nil
}

func Init() {
	mu.Lock()
	defer mu.Unlock()
	isInitialized = true

	// Validate already registered hooks if config is available
	conf := globals.GetConfig()
	log := globals.GetAppLogger()

	if NoExtensions {
		hooks = []registeredHook{}
		return
	}

	if conf != nil && !conf.Extensions.Enabled {
		hooks = []registeredHook{}
		return
	}

	if conf != nil {
		var validHooks []registeredHook
		for _, rh := range hooks {
			// In a real scenario, we might want to store the secret provided during Register
			// to re-validate here, but since Register happened, we trust it for now
			// or we could change Register to only work after Init.
			// Given the requirement of "init()" in golyn-ai, we must handle early registration.
			if _, ok := conf.Extensions.Whitelist[rh.id]; ok {
				validHooks = append(validHooks, rh)
			} else {
				if log != nil {
					log.Error("[CRITICAL] Unauthorized extension found during init | id=%s", rh.id)
					log.Sync()
				}
			}
		}
		hooks = validHooks
	}
}

// Start executes all registered hooks in order.
func Start(ctx context.Context) error {
	if log := globals.GetAppLogger(); log != nil {
		log.Info(
			"Start() | lifecycle | starting | hooks=%d",
			len(hooks),
		)
	}

	for i, rh := range hooks {
		if log := globals.GetAppLogger(); log != nil {
			log.Debug(
				"Start() | lifecycle | starting hook | index=%d | id=%s | type=%T",
				i+1,
				rh.id,
				rh.hook,
			)
		}

		if err := rh.hook.OnStart(ctx); err != nil {
			if log := globals.GetAppLogger(); log != nil {
				log.Error(
					"Start() | lifecycle | hook start failed | index=%d | id=%s | type=%T | error=%v",
					i+1,
					rh.id,
					rh.hook,
					err,
				)
				log.Sync()
			}
			return err
		}
	}

	if log := globals.GetAppLogger(); log != nil {
		log.Info("Start() | lifecycle | all hooks started")
	}

	return nil
}

// Shutdown executes all hooks in reverse order.
func Shutdown(ctx context.Context) {
	if log := globals.GetAppLogger(); log != nil {
		log.Info(
			"Shutdown() | lifecycle | shutting down | hooks=%d",
			len(hooks),
		)
	}

	for i := len(hooks) - 1; i >= 0; i-- {
		rh := hooks[i]

		if log := globals.GetAppLogger(); log != nil {
			log.Debug(
				"Shutdown() | lifecycle | shutting down hook | index=%d | id=%s | type=%T",
				i+1,
				rh.id,
				rh.hook,
			)
		}

		if err := rh.hook.OnShutdown(ctx); err != nil {
			if log := globals.GetAppLogger(); log != nil {
				log.Error(
					"Shutdown() | lifecycle | hook shutdown failed | index=%d | id=%s | type=%T | error=%v",
					i+1,
					rh.id,
					rh.hook,
					err,
				)
				log.Sync()
			}
		}
	}

	if log := globals.GetAppLogger(); log != nil {
		log.Info("Shutdown() | lifecycle | shutdown complete")
	}
}
