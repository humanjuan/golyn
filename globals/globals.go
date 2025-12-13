package globals

import (
	"crypto/tls"
	"github.com/humanjuan/golyn/app"
	"github.com/humanjuan/golyn/config/loaders"
	"github.com/humanjuan/golyn/database"
	"github.com/humanjuan/golyn/internal/utils"
	"html/template"
	"sync"

	"github.com/humanjuan/acacia/v2"
)

var RenderTemplate = true
var (
	config              *loaders.Config
	dbInstance          *database.DBInstance
	appLogger           *acacia.Log
	dbLogger            *acacia.Log
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

func SetAppLogger(log *acacia.Log) {
	appLogger = log
}

func SetDBLogger(log *acacia.Log) {
	dbLogger = log
}

func GetAppLogger() *acacia.Log {
	return appLogger
}

func GetDBLogger() *acacia.Log {
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
