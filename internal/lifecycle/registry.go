package lifecycle

import "sync"

var (
	mu    sync.Mutex
	hooks []Hook
)

func Register(h Hook) {
	mu.Lock()
	defer mu.Unlock()
	hooks = append(hooks, h)
}

func All() []Hook {
	mu.Lock()
	defer mu.Unlock()
	return append([]Hook(nil), hooks...)
}
