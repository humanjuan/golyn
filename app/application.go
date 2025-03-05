package app

import (
	"github.com/gin-gonic/gin"
	"time"
)

type Info struct {
	ServerVersion           string
	GinVersion              string
	GoVersion               string
	ServerStartTime         time.Time
	CertificatePath         string
	NumGoroutinesInParallel int
	NumCPU                  int
	MemStatsInMB            float64
}

type Cert struct {
	Path string
	Key  string
}

type VirtualHost struct {
	HostName  string
	BasePath  string
	SiteGroup *gin.RouterGroup
}
