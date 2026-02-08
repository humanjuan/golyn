package test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/config/loaders"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/middlewares"
)

func TestCorsMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Setup mock logger
	logDir := t.TempDir()
	log, _ := loaders.InitLog("test_cors", logDir, "debug", 5, 1, false)
	globals.SetAppLogger(log)
	defer log.Close()

	t.Run("Allow exact origin with port", func(t *testing.T) {
		router := gin.New()

		// Mock site config in context
		router.Use(func(c *gin.Context) {
			c.Set("site_config", loaders.SiteConfig{
				Security: loaders.Security{
					AllowOrigin: []string{"https://golyn.humanjuan.local:5173"},
				},
			})
			c.Next()
		})
		router.Use(middlewares.CorsMiddleware())
		router.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://golyn.humanjuan.local:5173")
		req.Host = "golyn.humanjuan.local"

		router.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Allow-Origin") != "https://golyn.humanjuan.local:5173" {
			t.Errorf("Expected allowed origin, got %s", w.Header().Get("Access-Control-Allow-Origin"))
		}
	})

	t.Run("Allow dev origin with different port", func(t *testing.T) {
		globals.SetConfig(&loaders.Config{Server: loaders.Server{Dev: true}})
		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("site_config", loaders.SiteConfig{
				Security: loaders.Security{
					AllowOrigin: []string{"https://golyn.humanjuan.local"},
				},
			})
			c.Next()
		})
		router.Use(middlewares.CorsMiddleware())
		router.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://golyn.humanjuan.local:5173")
		req.Host = "golyn.humanjuan.local"

		router.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Allow-Origin") != "https://golyn.humanjuan.local:5173" {
			t.Errorf("Expected allowed dev origin, got %s", w.Header().Get("Access-Control-Allow-Origin"))
		}
	})

	t.Run("Block dev origin if scheme doesn't match", func(t *testing.T) {
		globals.SetConfig(&loaders.Config{Server: loaders.Server{Dev: true}})
		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("site_config", loaders.SiteConfig{
				Security: loaders.Security{
					AllowOrigin: []string{"https://golyn.humanjuan.local"},
				},
			})
			c.Next()
		})
		router.Use(middlewares.CorsMiddleware())

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://golyn.humanjuan.local:5173")
		req.Host = "golyn.humanjuan.local"

		router.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("Origin with different scheme should be blocked, but got %s", w.Header().Get("Access-Control-Allow-Origin"))
		}
	})
}
