package utils

import (
	"fmt"
	"io"
	"net"
	"net/http"
)

func GetIPAddresses() (string, string, error) {
	resp, err := http.Get("https://ifconfig.me/ip")
	if err != nil {
		return "", "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("[ERROR] Error closing public IP response: %v\n", err)
		}
	}(resp.Body)

	publicIPBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[ERROR] Error reading public IP response: %v\n", err)
	}
	publicIP := string(publicIPBytes)

	// Obtener la IP local
	var localIP string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return publicIP, "", err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			if ipnet.IP.IsPrivate() {
				localIP = ipnet.IP.String()
				break
			}
		}
	}

	return publicIP, localIP, nil
}
