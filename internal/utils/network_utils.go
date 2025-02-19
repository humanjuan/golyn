package utils

import (
	"github.com/jpengineer/logger"
	"io"
	"net"
	"net/http"
)

func GetIPAddresses(log *logger.Log) (string, string) {
	log.Debug("getIPAddresses()")
	resp, err := http.Get("https://ifconfig.me/ip")
	if err != nil {
		log.Error("Error obtaining public IP: %v", err)
		return "", ""
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Error("Error closing public IP response: %v", err)
		}
	}(resp.Body)

	publicIPBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("Error reading public IP response: %v", err)
	}
	publicIP := string(publicIPBytes)

	// Obtener la IP local
	var localIP string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Error("Error obtaining local IP addresses: %v", err)
		return publicIP, ""
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			if ipnet.IP.IsPrivate() {
				localIP = ipnet.IP.String()
				break
			}
		}
	}

	return publicIP, localIP
}
