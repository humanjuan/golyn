package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/app"
	"github.com/humanjuan/golyn/config/loaders"
	"github.com/humanjuan/golyn/globals"
	v1 "github.com/humanjuan/golyn/routes/api/v1"
)

func TestFacebookDeletionEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Setup mock logger
	logDir := t.TempDir()
	log, _ := loaders.InitLog("test_privacy", logDir, "debug", 5, 1, false)
	globals.SetAppLogger(log)
	defer log.Close()

	router := gin.New()
	v1Group := router.Group("/api/v1")
	serverInfo := &app.Info{ServerVersion: "test"}
	v1.RegisterPublicRoutes(v1Group, serverInfo)

	methods := []string{"GET", "POST"}
	for _, m := range methods {
		t.Run(m+" /api/v1/privacy/facebook/deletion", func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(m, "/api/v1/privacy/facebook/deletion", nil)
			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected 200 OK, got %d", w.Code)
			}

			var resp map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			if resp["status"] != "ok" {
				t.Errorf("Expected status ok, got %s", resp["status"])
			}
		})
	}
}
