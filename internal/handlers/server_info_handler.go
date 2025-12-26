package handlers

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/app"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
	"net/http"
	"os"
	"runtime"
	"syscall"
)

func Version(serverInfo *app.Info) gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		tlsVersion := utils.GetTLSVersion(c.Request)
		certPEM, err := os.ReadFile(serverInfo.CertificatePath)
		if err != nil {
			log.Error("version() | An error has occurred while trying to read the certificate | Path: %s | Error: %v", serverInfo.CertificatePath, err.Error())
			log.Sync()
			err = fmt.Errorf("an error has occurred while trying to read the certificate")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			return
		}
		// decode PEM block
		block, _ := pem.Decode(certPEM)
		if block == nil {
			log.Error("version() | An error has occurred while trying to decode PEM certificate | Path: %s | Error: %v", serverInfo.CertificatePath, err.Error())
			log.Sync()
			err = fmt.Errorf("an error has occurred while trying to decode PEM certificate")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			return
		}
		// certificate parse
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Error("version() | An error has occurred while trying to parse the certificate bytes | Path: %s | Error: %v", serverInfo.CertificatePath, err.Error())
			log.Sync()
			err = fmt.Errorf("an error has occurred while trying to parse the certificate bytes")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			return
		}

		log.Debug("[Certificate] Subject: %s | Issuer: %s | Serial Number: %s | Not Before: %s | Not After: %s",
			cert.Subject, cert.Issuer.Organization, cert.SerialNumber, cert.NotBefore, cert.NotAfter)

		var rusage syscall.Rusage
		var mem int64

		err = syscall.Getrusage(syscall.RUSAGE_SELF, &rusage)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		// Check for the operating system
		if runtime.GOOS == "darwin" {
			mem = rusage.Maxrss / 1024 / 1024
		} else {
			mem = rusage.Maxrss / 1024
		}

		data := make(map[string]interface{})
		data["serverStartTime"] = serverInfo.ServerStartTime
		data["serverVersion"] = serverInfo.ServerVersion
		data["goVersion"] = serverInfo.GoVersion
		data["ginVersion"] = serverInfo.GinVersion
		data["numGoroutinesInParallel"] = serverInfo.NumGoroutinesInParallel
		data["numCPU"] = serverInfo.NumCPU
		data["memStatsInMB"] = mem
		data["tlsVersion"] = tlsVersion
		data["certIssuer"] = cert.Issuer.Organization[0]
		data["certDateIssue"] = cert.NotBefore
		data["certExpirationDay"] = cert.NotAfter

		c.IndentedJSON(http.StatusOK, gin.H{
			"message": utils.GetCodeMessage(http.StatusOK),
			"data":    data,
		})
		return
	}
}
