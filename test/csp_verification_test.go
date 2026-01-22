/*
Package test provides integration and regression tests for the Golyn project.

csp_verification_test.go: Content Security Policy (CSP) Integration Test

This test validates that the Content Security Policy (CSP) is correctly applied
and merged between the global server configuration and individual site configurations.
It ensures that the SecurityHeadersMiddleware respects the additive nature of CSP.

1. Setup:
  - Initializes a mock server (httptest) with SecurityHeadersMiddleware.
  - Configures a global base CSP.
  - Creates temporary site configuration files with and without specific CSP rules.

2. Test Objectives:
  - Base CSP: Verify that sites without specific CSP still receive the global base policy.
  - Merged CSP: Confirm that site-specific CSP rules are correctly appended to the base policy.
  - Multi-line CSP: Ensure that complex, multi-line CSP rules in .conf files are parsed and applied.
  - Unknown Sites: Verify that even requests to unconfigured hosts receive the base global CSP.

3. Expected Results:
  - Header "Content-Security-Policy" is always present in responses.
  - Site-specific rules never overwrite but extend the base policy.
  - Malformed or unknown hosts still benefit from global security headers.

4. Execution:
  - Command: go test -v test/csp_verification_test.go
*/
package test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/app"
	"github.com/humanjuan/golyn/config/loaders"
	"github.com/humanjuan/golyn/globals"
	internalcfg "github.com/humanjuan/golyn/internal/config"
	"github.com/humanjuan/golyn/middlewares"
)

func TestCSPAlwaysApplied(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Setup environment
	if os.Getenv("GOLYN_BASE_PATH") == "" {
		cwd, _ := os.Getwd()
		base := cwd
		if filepath.Base(base) == "test" {
			base = filepath.Dir(base)
		}
		os.Setenv("GOLYN_BASE_PATH", base)
	}

	baseCSP := "default-src 'self'; script-src 'self';"
	conf := &loaders.Config{
		Server: loaders.Server{
			Dev:                   true,
			ContentSecurityPolicy: baseCSP,
			PermissionsPolicy:     "camera=()",
			SitesRootPath:         t.TempDir(),
		},
	}
	globals.SetConfig(conf)

	log, _ := loaders.InitLog("test_csp", t.TempDir(), "debug", 5, 1, false)
	globals.SetAppLogger(log)

	siteProvider := internalcfg.NewSiteProvider()

	tempDir := t.TempDir()

	noCSPPath := filepath.Join(tempDir, "nocsp.conf")
	os.MkdirAll(filepath.Join(conf.Server.SitesRootPath, "nocsp"), 0755)
	os.WriteFile(noCSPPath, []byte("[settings]\nenabled=true\ndirectory=nocsp\ndomains=nocsp.local\nstaticFilesPath=./\njsPath=./\nstylePath=./\n"), 0644)

	withCSPPath := filepath.Join(tempDir, "withcsp.conf")
	os.MkdirAll(filepath.Join(conf.Server.SitesRootPath, "withcsp"), 0755)
	os.WriteFile(withCSPPath, []byte("[settings]\nenabled=true\ndirectory=withcsp\ndomains=withcsp.local\nstaticFilesPath=./\njsPath=./\nstylePath=./\ncontentSecurityPolicy=\"style-src 'self'\""), 0644)

	// Mock globals.VirtualHosts
	globals.VirtualHosts = map[string]app.VirtualHost{
		"nocsp.local": {
			HostName:   "nocsp.local",
			SiteName:   "nocsp",
			ConfigPath: noCSPPath,
		},
		"withcsp.local": {
			HostName:   "withcsp.local",
			SiteName:   "withcsp",
			ConfigPath: withCSPPath,
		},
	}

	middleware := middlewares.SecurityHeadersMiddleware(siteProvider, true)

	t.Run("Site without CSP - should have base CSP", func(t *testing.T) {
		router := gin.New()
		router.Use(middleware)
		router.GET("/", func(c *gin.Context) { c.String(200, "OK") })

		req, _ := http.NewRequest("GET", "/", nil)
		req.Host = "nocsp.local"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		csp := w.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'self'") {
			t.Errorf("Expected base CSP 'default-src 'self'' in header, got: %s", csp)
		}
	})

	t.Run("Site with CSP - should have merged CSP", func(t *testing.T) {
		router := gin.New()
		router.Use(middleware)
		router.GET("/", func(c *gin.Context) { c.String(200, "OK") })

		req, _ := http.NewRequest("GET", "/", nil)
		req.Host = "withcsp.local"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		csp := w.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'self'") {
			t.Errorf("Expected base CSP 'default-src 'self'' in header, got: %s", csp)
		}
		if !strings.Contains(csp, "style-src 'self'") {
			t.Errorf("Expected site CSP 'style-src 'self'' in header, got: %s", csp)
		}
	})

	t.Run("Site with multi-line CSP - should have merged CSP", func(t *testing.T) {
		multiCSPPath := filepath.Join(tempDir, "multiline.conf")
		os.MkdirAll(filepath.Join(conf.Server.SitesRootPath, "multiline"), 0755)
		os.WriteFile(multiCSPPath, []byte("[settings]\nenabled=true\ndirectory=multiline\ndomains=multiline.local\nstaticFilesPath=./\njsPath=./\nstylePath=./\ncontentSecurityPolicy=\"\"\"\nstyle-src 'self' https://fonts.googleapis.com;\nfont-src 'self' https://fonts.gstatic.com;\n\"\"\""), 0644)

		globals.VirtualHosts["multiline.local"] = app.VirtualHost{
			HostName:   "multiline.local",
			SiteName:   "multiline",
			ConfigPath: multiCSPPath,
		}

		router := gin.New()
		router.Use(middleware)
		router.GET("/", func(c *gin.Context) { c.String(200, "OK") })

		req, _ := http.NewRequest("GET", "/", nil)
		req.Host = "multiline.local"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		csp := w.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'self'") {
			t.Errorf("Expected base CSP 'default-src 'self'' in header, got: %s", csp)
		}
		if !strings.Contains(csp, "style-src 'self' https://fonts.googleapis.com") {
			t.Errorf("Expected multi-line site CSP 'style-src' in header, got: %s", csp)
		}
		if !strings.Contains(csp, "font-src 'self' https://fonts.gstatic.com") {
			t.Errorf("Expected multi-line site CSP 'font-src' in header, got: %s", csp)
		}
	})

	t.Run("Unknown site - should still have base CSP", func(t *testing.T) {
		router := gin.New()
		router.Use(middleware)
		router.GET("/", func(c *gin.Context) { c.String(200, "OK") })

		req, _ := http.NewRequest("GET", "/", nil)
		req.Host = "unknown.local"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		csp := w.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'self'") {
			t.Errorf("Expected base CSP 'default-src 'self'' for unknown site, got: %s", csp)
		}
	})
}
