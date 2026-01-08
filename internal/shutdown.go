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

	// Shutdown HTTP server
	if err := serverHTTP.Shutdown(ctx); err != nil {
		log.Error("Error shutting down HTTP server: %v", err)
		log.Sync()
	} else {
		log.Info("HTTP server shut down successfully.")
	}

	// Shutdown HTTPS server
	if err := serverTLS.Shutdown(ctx); err != nil {
		log.Error("Error shutting down HTTPS server: %v", err)
		log.Sync()
	} else {
		log.Info("HTTPS server shut down successfully.")
	}

	select {
	case <-ctx.Done():
		log.Info("Graceful shutdown timeout expired.")
	default:
		log.Info("All servers shut down gracefully.")
	}
	log.Info("Golyn it's gone.")
}
