package handlers

import (
	"Back/app"
	"Back/internal/utils"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/jpengineer/logger"
	"net/http"
	"os"
	"runtime"
	"syscall"
)

func Version(serverInfo *app.Info, log *logger.Log) gin.HandlerFunc {
	return func(c *gin.Context) {
		tlsVersion := utils.GetTLSVersion(c.Request)
		certPEM, err := os.ReadFile(serverInfo.CertificatePath)
		if err != nil {
			c.IndentedJSON(http.StatusInternalServerError, gin.H{
				"message": utils.GetCodeMessage(http.StatusInternalServerError),
				"error":   err.Error(),
			})
			log.Error(err.Error())
			return
		}
		// decode PEM block
		block, _ := pem.Decode(certPEM)
		if block == nil {
			c.IndentedJSON(http.StatusInternalServerError, gin.H{
				"message": utils.GetCodeMessage(http.StatusInternalServerError),
				"data":    "Couldn't decode PEM certificate",
			})
			log.Error("Couldn't decode PEM certificate")
			return
		}
		// certificate parse
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			c.IndentedJSON(http.StatusInternalServerError, gin.H{
				"message": utils.GetCodeMessage(http.StatusInternalServerError),
				"data":    err.Error(),
			})
			log.Error(err.Error())
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
