package internal

import (
	"Back/config/loaders"
	"Back/globals"
	"Back/internal/utils"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strconv"
	"time"
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
			log.Debug("SetupServerHTTPS | Domain %s has invalid certificate", domain)
		}
	}
	for domain := range globals.Certificates {
		log.Debug("SetupServerHTTPS | Valid certificate found for domain %s", domain)
	}
	globals.CertMutex.RUnlock()

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
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
			cert, err := tls.LoadX509KeyPair(site.Security.TLS_SSL.Cert, site.Security.TLS_SSL.Key)
			if err != nil {
				log.Error("loadAllCertificates() | Failed to load SSL certificate. Fallback to HTTP only | Site: %s | Error: %v", site.Directory, err.Error())
				globals.InvalidCertificates[domain] = true
				continue
			}

			// The  certificate is expired
			certs, err := x509.ParseCertificates(cert.Certificate[0])
			if err != nil {
				log.Error("loadAllCertificates() | Failed to parse certificate. Fallback to HTTP only | Site: %s | Error: %v", site.Directory, err.Error())
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
