package app

import (
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/config/loaders"
	"time"

	_ "github.com/humanjuan/acacia/v2"
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
	HostName    string
	BasePath    string
	SiteGroup   *gin.RouterGroup
	Proxy       bool
	ProxyTarget string
	Security    loaders.Security
	SMTP        loaders.SMTP
}
