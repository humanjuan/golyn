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

func TestCSRFProtection(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Disable error template rendering for tests
	globals.RenderTemplate = false

	// Mock config
	globals.SetConfig(&loaders.Config{
		Server: loaders.Server{
			CookieDomain: "", // Use empty for localhost/tests
			CookieSecure: false,
		},
	})

	// Setup mock logger
	logDir := t.TempDir()
	log, _ := loaders.InitLog("test_csrf", logDir, "debug", 5, 1, false)
	globals.SetAppLogger(log)
	// Do not close it immediately if tests run in parallel or if multiple tests use it
	// defer log.Close()

	router := gin.New()
	router.Use(middlewares.CustomErrorHandler())
	router.GET("/csrf-token", middlewares.GenerateCSRFToken)

	private := router.Group("/private", middlewares.CSRFMiddleware())
	{
		private.POST("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})
		private.PUT("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})
		private.DELETE("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})
		private.PATCH("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})
		private.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})
	}

	t.Run("GET request should pass without CSRF", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/private/test", nil)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("GET should not require CSRF, got %d", w.Code)
		}
	})

	t.Run("POST request without CSRF should fail", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/private/test", nil)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("POST without CSRF should be Forbidden, got %d", w.Code)
		}
	})

	t.Run("POST request with valid CSRF should pass", func(t *testing.T) {
		// 1. Get token
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest("GET", "/csrf-token", nil)
		router.ServeHTTP(w1, req1)

		var csrfCookie *http.Cookie
		for _, cookie := range w1.Result().Cookies() {
			if cookie.Name == "csrf_token" {
				csrfCookie = cookie
				break
			}
		}
		if csrfCookie == nil {
			t.Fatal("CSRF cookie not set")
		}

		// 2. Use token
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest("POST", "/private/test", nil)
		req2.AddCookie(csrfCookie)
		req2.Header.Set("X-CSRF-Token", csrfCookie.Value)
		// For debugging test failures
		// t.Logf("Cookie Value: %s, Header Value: %s", csrfCookie.Value, req2.Header.Get("X-CSRF-Token"))
		router.ServeHTTP(w2, req2)

		if w2.Code != http.StatusOK {
			t.Errorf("POST with valid CSRF should be OK, got %d. Body: %s", w2.Code, w2.Body.String())
		}
	})

	t.Run("PUT/DELETE/PATCH should also be protected", func(t *testing.T) {
		methods := []string{"PUT", "DELETE", "PATCH"}
		for _, m := range methods {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(m, "/private/test", nil)
			router.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Errorf("%s without CSRF should be Forbidden, got %d", m, w.Code)
			}
		}
	})
}
