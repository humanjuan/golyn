package utils

import (
	"crypto/tls"
	"net/http"
)

func GetTLSVersion(req *http.Request) string {
	if req.TLS != nil {
		switch req.TLS.Version {
		case tls.VersionTLS12:
			return "TLS 1.2"
		case tls.VersionTLS13:
			return "TLS 1.3"
		default:
			return "Unknown"
		}
	}
	return "Don't use TLS"
}
