package test

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// TestTLSVersions validates that TLS 1.2 and 1.3 are supported and that TLS 1.0 and 1.1 are not.
func TestTLSVersions(t *testing.T) {

	addr := "golyn.humanjuan.local:443"
	serverName := "golyn.humanjuan.local"

	t.Run("TLS1.2 supported", func(t *testing.T) {
		if ok, err := attemptTLSHandshake(addr, serverName, tls.VersionTLS12); !ok {
			t.Fatalf("expected TLS 1.2 to be supported, handshake failed: %v", err)
		}
	})

	t.Run("TLS1.3 supported", func(t *testing.T) {
		if ok, err := attemptTLSHandshake(addr, serverName, tls.VersionTLS13); !ok {
			t.Fatalf("expected TLS 1.3 to be supported, handshake failed: %v", err)
		}
	})

	t.Run("TLS1.0 not supported", func(t *testing.T) {
		if ok, _ := attemptTLSHandshake(addr, serverName, tls.VersionTLS10); ok {
			t.Fatalf("expected TLS 1.0 to be NOT supported, but handshake succeeded")
		}
	})

	t.Run("TLS1.1 not supported", func(t *testing.T) {
		if ok, _ := attemptTLSHandshake(addr, serverName, tls.VersionTLS11); ok {
			t.Fatalf("expected TLS 1.1 to be NOT supported, but handshake succeeded")
		}
	})
}

func attemptTLSHandshake(addr, serverName string, version uint16) (bool, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, // We only validate protocol support here
		ServerName:         serverName,
		MinVersion:         version,
		MaxVersion:         version,
	}
	conn, err := tls.DialWithDialer(d, "tcp", addr, tlsCfg)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		return false, err
	}
	return true, nil
}
