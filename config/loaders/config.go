package loaders

import (
	"Back/internal/utils"
	"errors"
	"fmt"
	"github.com/go-ini/ini"
	"path/filepath"
	"runtime"
	"sync"
)

type StaticFiles struct {
	Assets string
	Js     string
	Style  string
}

type TLS_SSL struct {
	Cert  string
	Key   string
	Chain string
}

type Security struct {
	AllowOrigin   []string
	HTTPSRedirect bool
	TLS_SSL       TLS_SSL
}
type SiteConfig struct {
	Enabled     bool
	Path        string
	Directory   string
	Domains     []string
	StaticFiles StaticFiles
	Security    Security
}

type Database struct {
	Username string
	Password string
	Database string
	Schema   string
	Host     string
	Port     int
}

type Server struct {
	Dev                        bool
	Name                       string
	SitesRootPath              string
	Port                       int
	ReadTimeoutSecond          int
	WriteTimeoutSecond         int
	MaxHeaderMB                int
	MaxGoRoutineParallel       int
	AutoJWT                    bool
	TokenExpirationTime        int
	TokenExpirationRefreshTime int
}

type Cache struct {
	ExpirationTime  int
	CleanUpInterval int
}

type Log struct {
	Level     string
	Path      string
	MaxSizeMb int
	MaxBackup int
}

type Config struct {
	Database Database
	Server   Server
	Sites    []SiteConfig
	Cache    Cache
	Log      Log
}

func LoadConfig() (*Config, error) {
	var (
		sites    []SiteConfig
		database Database
		server   Server
		cache    Cache
		log      Log
	)

	basePath, err := utils.GetBasePath()
	if err != nil {
		return &Config{}, errors.New(fmt.Sprintf("Error finding base path: %v", err))
	}

	configFilePath := filepath.Join(basePath, "config", "server", "web_server.conf")

	cfg, err := ini.Load(configFilePath)
	if err != nil {
		return &Config{}, errors.New(fmt.Sprintf("Error loading configuration file %s: %v", configFilePath, err))
	}

	// Database Configuration
	dbSection := cfg.Section("database")
	database.Host = dbSection.Key("host").String()
	database.Port, _ = dbSection.Key("port").Int()
	database.Database = dbSection.Key("database").String()
	database.Schema = dbSection.Key("schema").String()
	database.Username = dbSection.Key("username").String()
	database.Password = dbSection.Key("password").String()

	// Server Configuration
	serverSection := cfg.Section("server")
	server.Dev, _ = serverSection.Key("dev").Bool()
	server.Name = serverSection.Key("name").String()
	server.SitesRootPath = serverSection.Key("sitesRootPath").String()
	server.Port, _ = serverSection.Key("port").Int()
	server.ReadTimeoutSecond, _ = serverSection.Key("readTimeoutSecond").Int()
	server.WriteTimeoutSecond, _ = serverSection.Key("writeTimeoutSecond").Int()
	server.MaxHeaderMB, _ = serverSection.Key("maxHeaderMB").Int()
	server.MaxGoRoutineParallel, _ = serverSection.Key("maxGoRoutineParallel").Int()
	server.AutoJWT, _ = serverSection.Key("autoJWT").Bool()
	server.TokenExpirationTime, _ = serverSection.Key("tokenExpirationTime").Int()
	server.TokenExpirationRefreshTime, _ = serverSection.Key("tokenExpirationRefreshTime").Int()

	if !filepath.IsAbs(server.SitesRootPath) {
		server.SitesRootPath = filepath.Join(basePath, server.SitesRootPath)
	}

	dirExists := utils.FileOrDirectoryExists(server.SitesRootPath)

	if !dirExists {
		return &Config{}, errors.New(fmt.Sprintf("A sites root path is missing."))
	}

	// Sites Configuration
	var mu sync.Mutex
	var wg sync.WaitGroup

	maxGoroutines := runtime.GOMAXPROCS(0)
	sem := make(chan struct{}, maxGoroutines)

	siteSection := cfg.Section("sites").KeysHash()
	for siteName, sitePath := range siteSection {
		sem <- struct{}{}
		wg.Add(1)
		go func(name, path string) {
			defer wg.Done()
			defer func() { <-sem }() // Libera el token
			site, err := loadSiteConfig(name, path, basePath, server)
			if err != nil {
				return
			}
			if site.Enabled {
				mu.Lock()
				sites = append(sites, site)
				mu.Unlock()
			}
		}(siteName, sitePath)
	}
	wg.Wait()

	// Cache Configuration
	cacheSection := cfg.Section("cache")
	cache.ExpirationTime, _ = cacheSection.Key("expirationTime").Int()
	cache.CleanUpInterval, _ = cacheSection.Key("cleanUpInterval").Int()

	// Log Configuration
	logSection := cfg.Section("log")
	log.Level = logSection.Key("level").String()
	log.Path = logSection.Key("path").String()
	log.MaxSizeMb, _ = logSection.Key("maxSizeMB").Int()
	log.MaxBackup, _ = logSection.Key("maxBackup").Int()

	if !filepath.IsAbs(log.Path) {
		log.Path = filepath.Join(basePath, log.Path)
	}

	dirExists = utils.FileOrDirectoryExists(log.Path)

	if !dirExists {
		return &Config{}, errors.New(fmt.Sprintf("A log directory is missing. Please create it manually."))
	}

	return &Config{
		Database: database,
		Server:   server,
		Sites:    sites,
		Cache:    cache,
		Log:      log,
	}, nil
}

func loadSiteConfig(name string, path string, basePath string, server Server) (SiteConfig, error) {
	var siteConfig SiteConfig
	var staticFiles StaticFiles
	var tls_ssl TLS_SSL
	var security Security

	if !filepath.IsAbs(path) {
		path = filepath.Join(basePath, path)
	}

	if !utils.FileOrDirectoryExists(server.SitesRootPath) {
		fmt.Printf("[ERROR] The sites directory '%s' does not exist\n", server.SitesRootPath)
		return siteConfig, fmt.Errorf("the sites directory '%s' does not exist", server.SitesRootPath)
	}

	siteConfigFile, err := ini.Load(path)
	if err != nil {
		fmt.Printf("[ERROR] Error loading the site configuration '%s': %v\n", name, err)
		return siteConfig, fmt.Errorf("error loading the site configuration '%s': %v", name, err)
	}

	siteSettings := siteConfigFile.Section("settings")

	// SITE CONFIG
	siteConfig.Path = path
	siteConfig.Enabled, _ = siteSettings.Key("enabled").Bool()

	if !siteConfig.Enabled {
		fmt.Printf("[INFO] Skipping site '%s' because it is disabled\n", name)
		return siteConfig, nil
	}

	siteConfig.Directory = siteSettings.Key("directory").String()
	siteConfig.Domains = siteSettings.Key("domains").Strings(",")

	// STATIC FILES
	staticFiles.Assets = siteSettings.Key("static_files_path").String()
	if !filepath.IsAbs(staticFiles.Assets) {
		staticFiles.Assets = filepath.Join(basePath, staticFiles.Assets)
	}
	if !utils.FileOrDirectoryExists(staticFiles.Assets) {
		fmt.Printf("[ERROR] The static file directory '%s' does not exist\n", staticFiles.Assets)
		return siteConfig, fmt.Errorf("the static file directory '%s' does not exist", staticFiles.Assets)
	}

	staticFiles.Js = siteSettings.Key("js_path").String()
	if !filepath.IsAbs(staticFiles.Js) {
		staticFiles.Js = filepath.Join(basePath, staticFiles.Js)
	}
	if !utils.FileOrDirectoryExists(staticFiles.Js) {
		fmt.Printf("[ERROR] The static file directory '%s' does not exist\n", staticFiles.Js)
		return siteConfig, fmt.Errorf("the static file directory '%s' does not exist", staticFiles.Js)
	}

	staticFiles.Style = siteSettings.Key("style_path").String()
	if !filepath.IsAbs(staticFiles.Style) {
		staticFiles.Style = filepath.Join(basePath, staticFiles.Style)
	}
	if !utils.FileOrDirectoryExists(staticFiles.Style) {
		fmt.Printf("[ERROR] The static file directory '%s' does not exist\n", staticFiles.Style)
		return siteConfig, fmt.Errorf("the static file directory '%s' does not exist", staticFiles.Style)
	}
	siteConfig.StaticFiles = staticFiles

	// SSL/TLS
	tls_ssl.Cert = siteSettings.Key("cert_path").String()
	tls_ssl.Key = siteSettings.Key("key_path").String()
	tls_ssl.Chain = siteSettings.Key("chain_path").String()
	security.TLS_SSL = tls_ssl

	// SECURITY
	security.AllowOrigin = siteSettings.Key("allow_origin").Strings(",")
	security.HTTPSRedirect, _ = siteSettings.Key("enable_https_redirect").Bool()
	siteConfig.Security = security

	return siteConfig, nil
}
