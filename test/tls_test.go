package test

import (
	"crypto/tls"
	"net"
	"testing"
)

func TestTLSVersions(t *testing.T) {
	server := "golyn.local:443"
	validateTLSVersions(t, server)
}

func validateTLSVersions(t *testing.T, server string) {
	versions := map[string]uint16{
		"TLS1.0": tls.VersionTLS10,
		"TLS1.1": tls.VersionTLS11,
		"TLS1.2": tls.VersionTLS12,
		"TLS1.3": tls.VersionTLS13,
	}

	for versionName, versionCode := range versions {
		t.Logf("Testing %s...", versionName)

		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         versionCode,
			MaxVersion:         versionCode,
		}

		conn, err := net.Dial("tcp", server)
		if err != nil {
			t.Errorf("[NOK] Failed to connect to server: %s", err.Error())
			continue
		}
		defer conn.Close()

		c := tls.Client(conn, tlsConfig)
		err = c.Handshake()
		if err != nil {
			t.Logf("[NOK] %s NOT SUPPORTED: %v", versionName, err)
		} else {
			t.Logf("[OK] %s SUPPORTED", versionName)
		}
		c.Close()
	}
}
