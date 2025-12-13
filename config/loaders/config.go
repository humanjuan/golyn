package loaders

import (
	"errors"
	"fmt"
	"golyn/internal/utils"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"

	"github.com/go-ini/ini"
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
	Proxy       bool
	ProxyTarget string
	StaticFiles StaticFiles
	Security    Security
	SMTP        SMTP
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

type SMTP struct {
	Host              string
	Port              int
	Username          string
	Password          string
	RateLimitRequests int
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
			defer func() { <-sem }() // token free
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
	var smtp SMTP
	var ok bool
	var err error

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

	sectionName := "settings"
	siteSettings := siteConfigFile.Section(sectionName)

	// SITE CONFIG
	siteConfig.Path = path
	siteConfig.Enabled, ok, err = CheckBool(siteSettings.Key("enabled"), true, sectionName, "enabled")
	if !ok {
		fmt.Printf("[ERROR] Error loading the site configuration '%s': %v\n", name, err)
		siteConfig.Enabled = false
	}

	if !siteConfig.Enabled {
		fmt.Printf("[INFO] Skipping site '%s' because it is disabled\n", name)
		return siteConfig, nil
	}

	siteConfig.Directory, ok, err = CheckString(siteSettings.Key("directory"), true, sectionName, "directory")
	if !ok {
		siteConfig.Enabled = false
		fmt.Printf("[ERROR] The site %s was deactivated due to incorrect configuration.\n", name)
		return siteConfig, fmt.Errorf("error loading the site configuration '%s': %v", name, err)
	}

	siteConfig.Domains = siteSettings.Key("domains").Strings(",")
	siteConfig.Proxy, ok, err = CheckBool(siteSettings.Key("proxy"), true, sectionName, "proxy")
	if !ok {
		fmt.Printf("[WARN] A problem has been detected in the proxy configuration. The 'proxy' "+
			"setting has been set to 'false' as the default value for the site %s.\n", name)
		siteConfig.Proxy = false
		siteConfig.ProxyTarget = ""
	}

	if siteConfig.Proxy {
		siteConfig.ProxyTarget, ok, err = CheckString(siteSettings.Key("proxy_target"), true, sectionName, "proxy_target")
		if !ok {
			siteConfig.Enabled = false
			fmt.Printf("[ERROR] The site %s was deactivated due to incorrect configuration with proxy. Proxy target is empty\n", name)
			return siteConfig, fmt.Errorf("error loading the site configuration '%s': %v", name, err)
		}
		fmt.Printf("[INFO] Skipping static files for site '%s' because it is a proxy\n", name)
	} else {
		// STATIC FILES
		staticFiles.Assets, ok, err = CheckString(siteSettings.Key("static_files_path"), true, sectionName, "static_files_path")
		if !ok {
			siteConfig.Enabled = false
			fmt.Printf("[ERROR] The site %s was deactivated due to incorrect configuration with static files. Static files path is empty\n", name)
			return siteConfig, fmt.Errorf("error loading the site configuration '%s': %v", name, err)
		}
		if !filepath.IsAbs(staticFiles.Assets) {
			staticFiles.Assets = filepath.Join(basePath, staticFiles.Assets)
		}
		if !utils.FileOrDirectoryExists(staticFiles.Assets) {
			fmt.Printf("[ERROR] The static file directory '%s' does not exist\n", staticFiles.Assets)
			return siteConfig, fmt.Errorf("the static file directory '%s' does not exist", staticFiles.Assets)
		}

		staticFiles.Js, ok, err = CheckString(siteSettings.Key("js_path"), true, sectionName, "js_path")
		if !ok {
			siteConfig.Enabled = false
			fmt.Printf("[ERROR] The site %s was deactivated due to incorrect configuration with static files. JS path is empty\n", name)
			return siteConfig, fmt.Errorf("error loading the site configuration '%s': %v", name, err)
		}
		if !filepath.IsAbs(staticFiles.Js) {
			staticFiles.Js = filepath.Join(basePath, staticFiles.Js)
		}
		if !utils.FileOrDirectoryExists(staticFiles.Js) {
			fmt.Printf("[ERROR] The static file directory '%s' does not exist\n", staticFiles.Js)
			return siteConfig, fmt.Errorf("the static file directory '%s' does not exist", staticFiles.Js)
		}

		staticFiles.Style, ok, err = CheckString(siteSettings.Key("style_path"), true, sectionName, "style_path")
		if !ok {
			siteConfig.Enabled = false
			fmt.Printf("[ERROR] The site %s was deactivated due to incorrect configuration with static files. Style path is empty\n", name)
			return siteConfig, fmt.Errorf("error loading the site configuration '%s': %v", name, err)
		}
		if !filepath.IsAbs(staticFiles.Style) {
			staticFiles.Style = filepath.Join(basePath, staticFiles.Style)
		}
		if !utils.FileOrDirectoryExists(staticFiles.Style) {
			fmt.Printf("[ERROR] The static file directory '%s' does not exist\n", staticFiles.Style)
			return siteConfig, fmt.Errorf("the static file directory '%s' does not exist", staticFiles.Style)
		}
		siteConfig.StaticFiles = staticFiles
	}

	// SSL/TLS
	tls_ssl.Cert, _, _ = CheckString(siteSettings.Key("cert_path"), false, sectionName, "cert_path")
	tls_ssl.Key, _, _ = CheckString(siteSettings.Key("key_path"), false, sectionName, "key_path")
	tls_ssl.Chain, _, _ = CheckString(siteSettings.Key("chain_path"), false, sectionName, "chain_path")
	security.TLS_SSL = tls_ssl

	// SECURITY
	security.AllowOrigin = siteSettings.Key("allow_origin").Strings(",")
	security.HTTPSRedirect, _ = siteSettings.Key("enable_https_redirect").Bool()
	siteConfig.Security = security

	// SMTP
	smtp.Host, _, _ = CheckString(siteSettings.Key("smtp_host"), false, sectionName, "smtp_host")
	smtp.Port, _, _ = CheckInt(siteSettings.Key("smtp_port"), false, sectionName, "smtp_port")
	smtp.Username, _, _ = CheckString(siteSettings.Key("smtp_user"), false, sectionName, "smtp_user")
	smtp.Password = os.ExpandEnv(siteSettings.Key("smtp_password").String())
	smtp.RateLimitRequests, _, _ = CheckInt(siteSettings.Key("smtp_ratelimit_requests"), false, sectionName, "smtp_rate_limit_requests")

	siteConfig.SMTP = smtp
	return siteConfig, nil
}

func CheckString(key *ini.Key, required bool, sectionName, fieldName string) (string, bool, error) {
	if key == nil {
		if required {
			return "", false, fmt.Errorf("missing required '%s' in [%s] section", fieldName, sectionName)
		}
		return "", true, nil
	}
	value := key.String()
	if required && value == "" {
		return "", false, fmt.Errorf("required '%s' in [%s] section is empty", fieldName, sectionName)
	}
	return value, true, nil
}

func CheckInt(key *ini.Key, required bool, sectionName, fieldName string) (int, bool, error) {
	if key == nil {
		if required {
			return 0, false, fmt.Errorf("missing required '%s' in [%s] section", fieldName, sectionName)
		}
		return 0, true, nil
	}
	valueStr := key.String()
	if required && valueStr == "" {
		return 0, false, fmt.Errorf("required '%s' in [%s] section is empty", fieldName, sectionName)
	}
	if valueStr == "" {
		return 0, true, nil
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return 0, false, fmt.Errorf("invalid '%s' in [%s] section: %v", fieldName, sectionName, err)
	}
	return value, true, nil
}

func CheckBool(key *ini.Key, required bool, sectionName, fieldName string) (bool, bool, error) {
	if key == nil {
		if required {
			return false, false, fmt.Errorf("missing required '%s' in [%s] section", fieldName, sectionName)
		}
		return false, true, nil
	}
	valueStr := key.String()
	if required && valueStr == "" {
		return false, false, fmt.Errorf("required '%s' in [%s] section is empty", fieldName, sectionName)
	}
	if valueStr == "" {
		return false, true, nil
	}
	value, err := strconv.ParseBool(valueStr)
	if err != nil {
		return false, false, fmt.Errorf("invalid '%s' in [%s] section: %v", fieldName, sectionName, err)
	}
	return value, true, nil
}
