/*
Package test provides integration and regression tests for the Golyn project.

tls_integration_test.go: TLS/SSL Handshake and Certificate Management Test

This test validates the HTTPS server setup and its ability to handle secure
connections using real certificates. It ensures that the multi-site
certificate loading mechanism works as expected.

1. Setup:
  - Initializes the application logger and global configuration.
  - Loads real certificates from the 'certificates/golyn' directory.
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
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/acacia/v2"
	"github.com/humanjuan/golyn/config/loaders"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal"
	"github.com/humanjuan/golyn/internal/utils"
)

func TestTLSIntegration(t *testing.T) {
	if os.Getenv("GOLYN_BASE_PATH") == "" {
		cwd, _ := os.Getwd()
		os.Setenv("GOLYN_BASE_PATH", cwd)
	}

	log, _ := acacia.Start("test_tls.log", "./var/log", "DEBUG")
	globals.SetAppLogger(log)
	defer func() {
		log.Sync()
		log.Close()
		os.Remove("./var/log/test_tls.log")
	}()

	basePath, err := utils.GetBasePath()
	if err != nil {
		t.Fatalf("Failed to get base path: %v", err)
	}

	// Host configuration
	testHost := "golyn.humanjuan.local"

	// Mock configuration
	conf := &loaders.Config{
		Server: loaders.Server{
			Name:               "GolynTLS",
			Port:               0, // Random port for testing
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
						Cert: basePath + "/certificates/golyn/cert.pem",
						Key:  basePath + "/certificates/golyn/privkey.pem",
					},
				},
			},
		},
	}
	globals.SetConfig(conf)

	// 2. Load Certificates
	globals.InitCertificates()
	err = internal.LoadAllCertificates(conf.Sites)
	if err != nil {
		t.Fatalf("Failed to load certificates: %v", err)
	}

	// Verify the certificate was loaded for the domain
	globals.CertMutex.RLock()
	_, exists := globals.Certificates[testHost]
	globals.CertMutex.RUnlock()
	if !exists {
		t.Fatalf("Certificate for %s was not loaded into globals", testHost)
	}

	// Setup Router and Server
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})

	server, err := internal.SetupServerHTTPS(router)
	if err != nil {
		t.Fatalf("Failed to setup HTTPS server: %v", err)
	}

	// Create a listener on a random port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer ln.Close()

	// Update server address to the actual listener address
	server.Addr = ln.Addr().String()

	// Start server in a goroutine
	go func() {
		_ = server.ServeTLS(ln, "", "")
	}()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)

	tlsClientConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         testHost,
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsClientConfig,
		},
		Timeout: 5 * time.Second,
	}

	url := fmt.Sprintf("https://%s/ping", server.Addr)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	// The Host header must match the expected host for Gin/Middlewares
	req.Host = testHost

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify certificate details from connection
	if resp.TLS == nil {
		t.Fatal("Response TLS is nil, expected secure connection")
	}

	if len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("No peer certificates found in TLS connection")
	}

	t.Logf("[OK] TLS Handshake successful with host %s", testHost)
	t.Logf("[OK] Certificate Issuer: %s", resp.TLS.PeerCertificates[0].Issuer)

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
		defer conn.Close()
		t.Log("[OK] TLS 1.2 connection established")
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
		defer conn.Close()
		t.Log("[OK] TLS 1.3 connection established")
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
			t.Fatal("Expected TLS 1.1 handshake to fail, but it succeeded")
		}
		t.Logf("[OK] TLS 1.1 connection rejected as expected: %v", err)
	})
}
