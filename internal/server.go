package internal

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/humanjuan/golyn/config/loaders"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
)

func SetupServerHTTPS(router http.Handler) (*http.Server, error) {
	log := globals.GetAppLogger()
	log.Debug("setupServerHTTPS()")
	config := globals.GetConfig()

	globals.CertMutex.RLock()
	hasValidCerts := len(globals.Certificates) > 0
	hasInvalidDomains := false
	for domain, invalid := range globals.InvalidCertificates {
		if invalid {
			hasInvalidDomains = true
			log.Debug("SetupServerHTTPS() | Domain %s has invalid certificate", domain)
		}
	}
	for domain := range globals.Certificates {
		log.Debug("SetupServerHTTPS() | Valid certificate found for domain %s", domain)
	}
	globals.CertMutex.RUnlock()

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		GetCertificate: func(clientHelloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
			globals.CertMutex.RLock()
			defer globals.CertMutex.RUnlock()
			if cert, ok := globals.Certificates[clientHelloInfo.ServerName]; ok {
				if globals.InvalidCertificates[clientHelloInfo.ServerName] {
					log.Debug("SetupServerHTTPS | Certificate for domain %s is invalid, returning error", clientHelloInfo.ServerName)
					return nil, fmt.Errorf("SetupServerHTTPS() | Certificate for domain %s is invalid", clientHelloInfo.ServerName)
				}
				return &cert, nil
			}
			return nil, fmt.Errorf("setupServerHTTPS() | No valid certificate found. Falling back to error handling | Site: %s", clientHelloInfo.ServerName)
		},
		InsecureSkipVerify: config.Server.Dev,
	}

	server := &http.Server{
		Addr:           "0.0.0.0:" + strconv.Itoa(config.Server.Port),
		Handler:        router,
		ReadTimeout:    time.Duration(config.Server.ReadTimeoutSecond) * time.Second,
		WriteTimeout:   time.Duration(config.Server.WriteTimeoutSecond) * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: config.Server.MaxHeaderMB * 1024 * 1024,
		TLSConfig:      tlsConfig,
	}

	if !hasValidCerts {
		log.Warn("setupServerHTTPS() | No valid certificates found globally, but HTTPS server will handle errors.")
	}
	if hasInvalidDomains {
		log.Warn("setupServerHTTPS() | Some sites have invalid certificates, but HTTPS server will handle errors.")
	}
	return server, nil
}

func SetupServerHTTP(router http.Handler) (*http.Server, error) {
	log := globals.GetAppLogger()
	log.Debug("SetupServerHTTP()")

	// HTTP server for port 80
	serverHTTP := &http.Server{
		Addr:    "0.0.0.0:80",
		Handler: router,
	}
	return serverHTTP, nil
}

func LoadAllCertificates(sites []loaders.SiteConfig) error {
	log := globals.GetAppLogger()
	globals.CertMutex.Lock()
	defer globals.CertMutex.Unlock()

	for _, site := range sites {
		for _, domain := range site.Domains {
			if site.Security.TLS_SSL.Cert == "" || site.Security.TLS_SSL.Key == "" {
				log.Warn("loadAllCertificates() | No TLS certificate paths found. Fallback to HTTP only | Site: %s", site.Directory)
				globals.InvalidCertificates[domain] = true
				continue
			}
			if !utils.FileOrDirectoryExists(site.Security.TLS_SSL.Cert) {
				log.Warn("loadAllCertificates() | Certificate file missing. Fallback to HTTP only | Path: %s | Site: %s", site.Security.TLS_SSL.Cert, site.Directory)
				globals.InvalidCertificates[domain] = true
				continue
			}
			if !utils.FileOrDirectoryExists(site.Security.TLS_SSL.Key) {
				log.Warn("loadAllCertificates() | Private key file missing. Fallback to HTTP only | Path: %s | Site: %s", site.Security.TLS_SSL.Key, site.Directory)
				globals.InvalidCertificates[domain] = true
				continue
			}

			// Load certificate
			var cert tls.Certificate
			var err error

			// Load the main certificate and private key
			cert, err = tls.LoadX509KeyPair(site.Security.TLS_SSL.Cert, site.Security.TLS_SSL.Key)
			if err != nil {
				log.Error("loadAllCertificates() | Failed to load SSL certificate. Fallback to HTTP only | Site: %s | Error: %v", site.Directory, err.Error())
				log.Sync()
				globals.InvalidCertificates[domain] = true
				continue
			}

			// If we have a chain file, we load all certificates from it and replace/append to the certificate list
			if site.Security.TLS_SSL.Chain != "" && utils.FileOrDirectoryExists(site.Security.TLS_SSL.Chain) {
				chainData, err := os.ReadFile(site.Security.TLS_SSL.Chain)
				if err == nil {
					var chainCerts [][]byte
					for {
						var block *pem.Block
						block, chainData = pem.Decode(chainData)
						if block == nil {
							break
						}
						if block.Type == "CERTIFICATE" {
							chainCerts = append(chainCerts, block.Bytes)
						}
					}
					if len(chainCerts) > 0 {
						cert.Certificate = chainCerts
					}
				} else {
					log.Warn("loadAllCertificates() | Failed to read chain file for extra certificates | Site: %s | Error: %v", site.Directory, err.Error())
				}
			}

			// The certificate is expired
			certs, err := x509.ParseCertificates(cert.Certificate[0])
			if err != nil {
				log.Error("loadAllCertificates() | Failed to parse certificate. Fallback to HTTP only | Site: %s | Error: %v", site.Directory, err.Error())
				log.Sync()
				globals.InvalidCertificates[domain] = true
				continue
			}
			if len(certs) > 0 && time.Now().After(certs[0].NotAfter) {
				log.Warn("loadAllCertificates() | Certificate expired. Fallback to HTTP only | Site: %s | Expiration: %v", site.Directory, certs[0].NotAfter)
				globals.InvalidCertificates[domain] = true
				continue
			}

			// Store certificate for each domain
			globals.Certificates[domain] = cert
			log.Debug("LoadAllCertificates() | Valid certificate loaded for domain %s | Site: %s", domain, site.Directory)
		}
	}
	return nil
}
