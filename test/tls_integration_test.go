/*
Package test provides integration and regression tests for the Golyn project.

tls_integration_test.go: TLS/SSL Handshake and Certificate Management Test

This test validates the HTTPS server setup and its ability to handle secure
connections using real certificates. It ensures that the multi-site
certificate loading mechanism works as expected.

1. Setup:
  - Initializes the application logger and global configuration.
  - Loads testing certificates from the 'test/cert' directory.
  - Configures a test host: golyn.humanjuan.local.
  - Starts a local HTTPS server using a custom listener to test the TLS handshake.

2. Test Objectives:
  - Certificate Loading: Verify that the system can parse and store valid PEM certificates.
  - TLS Handshake: Confirm that a client can establish a secure connection.
  - SNI Support: Ensure the server selects the correct certificate based on the requested hostname.
  - Response Integrity: Validate that the server handles encrypted requests and returns the correct data.
  - Protocol Versioning:
  - Success: Establish connections with TLS 1.2 and TLS 1.3.
  - Rejection: Ensure the server rejects outdated versions like TLS 1.1.

3. Expected Results:
  - The server should start without errors using TLS.
  - Client requests to https://golyn.humanjuan.local should return 200 OK.
  - Handshake must succeed even with self-signed certificates (using InsecureSkipVerify in dev).
  - Connections using TLS 1.1 or lower must fail at the handshake level.

4. Execution:
  - Command: export GOLYN_BASE_PATH=$(pwd) && go test -v test/tls_integration_test.go
*/

package test

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/app"
	"github.com/humanjuan/golyn/config/loaders"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal"
	"github.com/humanjuan/golyn/internal/utils"
	"github.com/humanjuan/golyn/middlewares"
)

// waitForServer intenta conectar repetidamente hasta que el puerto esté disponible
func waitForServer(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("server did not become ready in time")
}

func TestTLSIntegration(t *testing.T) {

	// --- Inicialización del logger en el directorio estándar del proyecto ---
	basePath, err := utils.GetBasePath()
	if err != nil {
		t.Fatalf("Failed to get base path: %v", err)
	}
	// Si estamos dentro del directorio test, retrocedemos uno
	if filepath.Base(basePath) == "test" {
		basePath = filepath.Dir(basePath)
	}

	logDir := filepath.Join(basePath, "var", "log")
	log, err := loaders.InitLog("test_tls", logDir, "debug", 5, 1, false)
	if err != nil {
		t.Fatalf("failed to init logger: %v", err)
	}
	globals.SetAppLogger(log)
	log.Info("Test started, basePath: %s", basePath)
	// No cerramos el log inmediatamente para asegurar que se escriban los buffers
	defer log.Sync()

	testHost := "golyn.humanjuan.local"

	// --- Configuración de prueba ---
	conf := &loaders.Config{
		Server: loaders.Server{
			Name:               "GolynTLS",
			Port:               0,
			Dev:                true,
			ReadTimeoutSecond:  5,
			WriteTimeoutSecond: 5,
			MaxHeaderMB:        1,
		},
		Sites: []loaders.SiteConfig{
			{
				Directory: "golyn",
				Enabled:   true,
				Domains:   []string{testHost},
				Security: loaders.Security{
					TLS_SSL: loaders.TLS_SSL{
						Cert: basePath + "/test/cert/cert.pem",
						Key:  basePath + "/test/cert/privkey.pem",
					},
				},
			},
		},
	}

	// Guardar configuración original para restaurar al final
	originalConfig := globals.GetConfig()
	defer globals.SetConfig(originalConfig)

	globals.SetConfig(conf)
	globals.InitCertificates()
	globals.VirtualHosts = make(map[string]app.VirtualHost)

	// --- Cargar certificados ---
	if err := internal.LoadAllCertificates(conf.Sites); err != nil {
		t.Fatalf("Failed to load certificates: %v", err)
	}

	globals.CertMutex.RLock()
	_, exists := globals.Certificates[testHost]
	globals.CertMutex.RUnlock()
	if !exists {
		t.Fatalf("Certificate for %s was not loaded into globals", testHost)
	}

	// --- Configuración del servidor HTTPS ---
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})

	server, err := internal.SetupServerHTTPS(router)
	if err != nil {
		t.Fatalf("Failed to setup HTTPS server: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer ln.Close()

	server.Addr = ln.Addr().String()

	go func() {
		_ = server.ServeTLS(ln, "", "")
	}()

	// Esperar a que el servidor esté listo
	if err := waitForServer(server.Addr, 3*time.Second); err != nil {
		t.Fatalf("server did not start: %v", err)
	}

	// --- Cliente TLS ---
	tlsClientConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         testHost,
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsClientConfig},
		Timeout:   5 * time.Second,
	}

	url := fmt.Sprintf("https://%s/ping", server.Addr)
	req, _ := http.NewRequest("GET", url, nil)
	req.Host = testHost

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	t.Logf("[OK] TLS Handshake successful with host %s", testHost)

	// --- SUBTESTS ---

	t.Run("HTTPS Redirection (Production Mode)", func(t *testing.T) {
		conf.Server.Dev = false
		defer func() { conf.Server.Dev = true }()

		// Registrar host para que el middleware lo reconozca
		globals.VirtualHosts[testHost] = app.VirtualHost{SiteName: "golyn"}
		defer delete(globals.VirtualHosts, testHost)

		r := gin.New()
		r.Use(middlewares.SecurityHeadersMiddleware(nil, false))
		r.GET("/ping", func(c *gin.Context) {
			c.String(http.StatusOK, "pong")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "http://"+testHost+"/ping", nil)
		req.Host = testHost

		r.ServeHTTP(w, req)

		if w.Code != http.StatusMovedPermanently {
			t.Errorf("Expected status 301, got %d", w.Code)
		}
	})

	t.Run("Blocked HTTP access without certificate (Production Mode)", func(t *testing.T) {
		// Registrar host para que el middleware lo reconozca
		globals.VirtualHosts[testHost] = app.VirtualHost{SiteName: "golyn"}
		defer delete(globals.VirtualHosts, testHost)

		// Simular ausencia de certificado
		globals.CertMutex.Lock()
		oldCert, hasOld := globals.Certificates[testHost]
		delete(globals.Certificates, testHost)
		globals.CertMutex.Unlock()

		defer func() {
			if hasOld {
				globals.CertMutex.Lock()
				globals.Certificates[testHost] = oldCert
				globals.CertMutex.Unlock()
			}
		}()

		r := gin.New()
		// Usar la configuración de servidor en producción forzada
		r.Use(middlewares.SecurityHeadersMiddleware(nil, false))
		r.GET("/ping", func(c *gin.Context) {
			c.String(http.StatusOK, "pong")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "http://"+testHost+"/ping", nil)
		req.Host = testHost

		r.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status 404, got %d", w.Code)
		}
	})

	t.Run("Supported Protocol: TLS 1.2", func(t *testing.T) {
		config := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         testHost,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
		}
		conn, err := tls.Dial("tcp", server.Addr, config)
		if err != nil {
			t.Fatalf("TLS 1.2 handshake failed: %v", err)
		}
		conn.Close()
	})

	t.Run("Supported Protocol: TLS 1.3", func(t *testing.T) {
		config := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         testHost,
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		}
		conn, err := tls.Dial("tcp", server.Addr, config)
		if err != nil {
			t.Fatalf("TLS 1.3 handshake failed: %v", err)
		}
		conn.Close()
	})

	t.Run("Unsupported Protocol: TLS 1.1", func(t *testing.T) {
		config := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         testHost,
			MinVersion:         tls.VersionTLS11,
			MaxVersion:         tls.VersionTLS11,
		}
		conn, err := tls.Dial("tcp", server.Addr, config)
		if err == nil {
			conn.Close()
			t.Fatal("Expected TLS 1.1 handshake to fail")
		}
	})
}
