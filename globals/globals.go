package globals

import (
	"Back/app"
	"Back/config/loaders"
	"Back/database"
	"Back/internal/utils"
	"crypto/tls"
	"github.com/humanjuan/logger"
	"html/template"
	"sync"
)

var RenderTemplate = true
var (
	config              *loaders.Config
	dbInstance          *database.DBInstance
	appLogger           *logger.Log
	dbLogger            *logger.Log
	ErrorTemplate       *template.Template
	VirtualHosts        map[string]app.VirtualHost
	DefaultSite         string
	Certificates        map[string]tls.Certificate
	InvalidCertificates map[string]bool
	CertMutex           sync.RWMutex
	CertificateError    *utils.HTTPError
)

func SetConfig(conf *loaders.Config) {
	config = conf
}

func GetConfig() *loaders.Config {
	return config
}

func SetDBInstance(db *database.DBInstance) {
	dbInstance = db
}

func GetDBInstance() *database.DBInstance {
	return dbInstance
}

func SetAppLogger(log *logger.Log) {
	appLogger = log
}

func SetDBLogger(log *logger.Log) {
	dbLogger = log
}

func GetAppLogger() *logger.Log {
	return appLogger
}

func GetDBLogger() *logger.Log {
	return dbLogger
}

func InitCertificates() {
	CertMutex.Lock()
	defer CertMutex.Unlock()
	if Certificates == nil {
		Certificates = make(map[string]tls.Certificate)
	}
	if InvalidCertificates == nil {
		InvalidCertificates = make(map[string]bool)
	}
}

func SetCertificateError(err *utils.HTTPError) {
	CertificateError = err
}

func GetCertificateError() *utils.HTTPError {
	return CertificateError
}
