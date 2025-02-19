package internal

import (
	"Back/app"
	"Back/config/loaders"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

func SetupServerHTTPS(conf *loaders.Config, router http.Handler, certificate *app.Cert) (*http.Server, error) {
	cert, err := tls.LoadX509KeyPair(certificate.Path, certificate.Key)
	if err != nil {
		return nil, errors.New("Error loading TLS certificates: " + err.Error())
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: conf.Server.Dev,
	}

	server := &http.Server{
		Addr:           "0.0.0.0:" + strconv.Itoa(conf.Server.Port),
		Handler:        router,
		ReadTimeout:    time.Duration(conf.Server.ReadTimeoutSecond) * time.Second,
		WriteTimeout:   time.Duration(conf.Server.WriteTimeoutSecond) * time.Second,
		MaxHeaderBytes: conf.Server.MaxHeaderMB * 1024 * 1024,
		TLSConfig:      tlsConfig,
	}
	return server, nil
}

func SetupServerHTTP() (*http.Server, error) {

	// HTTP server for port 80
	serverHTTP := &http.Server{
		Addr: "0.0.0.0:80",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Println("HTTP to HTTPS redirect")
			target := "https://" + r.Host + r.URL.String()
			fmt.Println(target)
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		}),
	}
	return serverHTTP, nil
}
