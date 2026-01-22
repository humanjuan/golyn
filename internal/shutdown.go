package internal

import (
	"context"
	"github.com/humanjuan/golyn/globals"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func shutdownServer(ctx context.Context, server *http.Server, name string) {
	if server == nil {
		return
	}
	log := globals.GetAppLogger()
	if err := server.Shutdown(ctx); err != nil {
		log.Error("Error shutting down %s server: %v", name, err)
		log.Sync()
	} else {
		log.Info("%s server shut down successfully.", name)
	}
}

func CatchSignalDual(serverTLS, serverHTTP *http.Server) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	log := globals.GetAppLogger()

	<-quit
	log.Info("catchSignalDual() | Managing graceful shutdown for both servers")
	log.Info("catchSignalDual() | Received shutdown signal. Shutting down servers...")

	log.Info("Emmett HTTPS Brown: Good look for both of our sake")
	log.Info("Emmett HTTPS Brown:: See you in the future")
	log.Info("Marty HTTP McFly: You mean the past")
	log.Info("Emmett HTTPS Brown: Exactly!")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Shutdown servers
	shutdownServer(ctx, serverHTTP, "HTTP")
	shutdownServer(ctx, serverTLS, "HTTPS")

	select {
	case <-ctx.Done():
		log.Info("Graceful shutdown timeout expired.")
	default:
		log.Info("All servers shut down gracefully.")
	}
	log.Info("Golyn it's gone.")
}
