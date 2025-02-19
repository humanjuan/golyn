package app

import (
	"Back/config/loaders"
	"Back/database"
	"github.com/gin-gonic/gin"
	"github.com/jpengineer/logger"
	"time"
)

type Application struct {
	DB     *database.DBInstance
	LogDB  *logger.Log
	LogApp *logger.Log
	Config *loaders.Config
}

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
