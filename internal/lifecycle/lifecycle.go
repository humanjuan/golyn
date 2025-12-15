package lifecycle

import "context"

type Hook interface {
	OnStart(ctx context.Context) error
	OnShutdown(ctx context.Context) error
}
