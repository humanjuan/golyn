package loaders

import (
	"Back/internal/utils"
	"errors"
	"fmt"
	"github.com/go-ini/ini"
	"log"
	"path/filepath"
)

type SiteConfig struct {
	Enabled     bool
	Path        string
	Directory   string
	Domains     []string
	StaticFiles struct {
		Assets string
		Js     string
		Style  string
	}
	Security struct {
		AllowOrigin   []string
		HTTPSRedirect bool
	}
}

type Config struct {
	Database struct {
		Username string
		Password string
		Database string
		Schema   string
		Host     string
		Port     int
	}
	Server struct {
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
	Sites []SiteConfig
	Cache struct {
		ExpirationTime  int
		CleanUpInterval int
	}
	Log struct {
		Level     string
		Path      string
		MaxSizeMb int
		MaxBackup int
	}
}

func LoadConfig() (*Config, error) {
	var conf Config
	// defaultSite := "golyn"

	basePath, err := utils.GetBasePath()
	if err != nil {
		return &Config{}, errors.New(fmt.Sprintf("Error finding base path: %v", err))
	}

	configFilePath := filepath.Join(basePath, "config", "server", "web_server.conf")

	cfg, err := ini.Load(configFilePath)
	if err != nil {
		return &Config{}, errors.New(fmt.Sprintf("Error loading configuration: %v\n", err))
	}

	// Database Configuration
	dbSection := cfg.Section("database")
	conf.Database.Host = dbSection.Key("host").String()
	conf.Database.Port, _ = dbSection.Key("port").Int()
	conf.Database.Database = dbSection.Key("database").String()
	conf.Database.Schema = dbSection.Key("schema").String()
	conf.Database.Username = dbSection.Key("username").String()
	conf.Database.Password = dbSection.Key("password").String()

	// Server Configuration
	serverSection := cfg.Section("server")
	conf.Server.Dev, _ = serverSection.Key("dev").Bool()
	conf.Server.Name = serverSection.Key("name").String()
	conf.Server.SitesRootPath = serverSection.Key("sitesRootPath").String()
	conf.Server.Port, _ = serverSection.Key("port").Int()
	conf.Server.ReadTimeoutSecond, _ = serverSection.Key("readTimeoutSecond").Int()
	conf.Server.WriteTimeoutSecond, _ = serverSection.Key("writeTimeoutSecond").Int()
	conf.Server.MaxHeaderMB, _ = serverSection.Key("maxHeaderMB").Int()
	conf.Server.MaxGoRoutineParallel, _ = serverSection.Key("maxGoRoutineParallel").Int()
	conf.Server.AutoJWT, _ = serverSection.Key("autoJWT").Bool()
	conf.Server.TokenExpirationTime, _ = serverSection.Key("tokenExpirationTime").Int()
	conf.Server.TokenExpirationRefreshTime, _ = serverSection.Key("tokenExpirationRefreshTime").Int()

	if !filepath.IsAbs(conf.Server.SitesRootPath) {
		conf.Server.SitesRootPath = filepath.Join(basePath, conf.Server.SitesRootPath)
	}

	dirExists := utils.FileOrDirectoryExists(conf.Server.SitesRootPath)

	if !dirExists {
		return &Config{}, errors.New(fmt.Sprintf("A sites root path is missing."))
	}

	// Sites Configuration
	siteSection := cfg.Section("sites").KeysHash()
	for siteName, sitePath := range siteSection {
		if !filepath.IsAbs(sitePath) {
			sitePath = filepath.Join(basePath, sitePath)
		}

		if !utils.FileOrDirectoryExists(conf.Server.SitesRootPath) {
			fmt.Printf("[ERROR] The sites directory '%s' does not exist\n", sitePath)
			continue
		}

		siteConfigFile, err := ini.Load(sitePath)
		if err != nil {
			log.Printf("[ERROR] Error loading the site configuration '%s': %v\n", siteName, err)
			continue
		}

		siteSettings := siteConfigFile.Section("settings")
		siteConfig := SiteConfig{}
		siteConfig.Path = sitePath
		siteConfig.Enabled, _ = siteSettings.Key("enabled").Bool()

		if !siteConfig.Enabled {
			fmt.Printf("[INFO] Skipping site '%s' because it is disabled\n", siteName)
			continue
		}

		siteConfig.Directory = siteSettings.Key("directory").String()
		siteConfig.Domains = siteSettings.Key("domains").Strings(",")
		siteConfig.StaticFiles.Assets = siteSettings.Key("static_files_path").String()

		if !filepath.IsAbs(siteConfig.StaticFiles.Assets) {
			siteConfig.StaticFiles.Assets = filepath.Join(basePath, siteConfig.StaticFiles.Assets)
		}

		if !utils.FileOrDirectoryExists(siteConfig.StaticFiles.Assets) {
			fmt.Printf("[ERROR] The static file directory '%s' does not exist\n", siteConfig.StaticFiles.Assets)
			continue
		}

		siteConfig.StaticFiles.Js = siteSettings.Key("js_path").String()

		if !filepath.IsAbs(siteConfig.StaticFiles.Js) {
			siteConfig.StaticFiles.Js = filepath.Join(basePath, siteConfig.StaticFiles.Js)
		}

		if !utils.FileOrDirectoryExists(siteConfig.StaticFiles.Js) {
			fmt.Printf("[ERROR] The static file directory '%s' does not exist\n", siteConfig.StaticFiles.Js)
			continue
		}

		siteConfig.StaticFiles.Style = siteSettings.Key("style_path").String()

		if !filepath.IsAbs(siteConfig.StaticFiles.Style) {
			siteConfig.StaticFiles.Style = filepath.Join(basePath, siteConfig.StaticFiles.Style)
		}

		if !utils.FileOrDirectoryExists(siteConfig.StaticFiles.Style) {
			fmt.Printf("[ERROR] The static file directory '%s' does not exist\n", siteConfig.StaticFiles.Style)
			continue
		}

		siteConfig.Security.AllowOrigin = siteSettings.Key("allow_origin").Strings(",")
		siteConfig.Security.HTTPSRedirect, _ = siteSettings.Key("https_redirect").Bool()

		conf.Sites = append(conf.Sites, siteConfig)
	}

	// Cache Configuration
	cacheSection := cfg.Section("cache")
	conf.Cache.ExpirationTime, _ = cacheSection.Key("expirationTime").Int()
	conf.Cache.CleanUpInterval, _ = cacheSection.Key("cleanUpInterval").Int()

	// Log Configuration
	logSection := cfg.Section("log")
	conf.Log.Level = logSection.Key("level").String()
	conf.Log.Path = logSection.Key("path").String()
	conf.Log.MaxSizeMb, _ = logSection.Key("maxSizeMB").Int()
	conf.Log.MaxBackup, _ = logSection.Key("maxBackup").Int()

	if !filepath.IsAbs(conf.Log.Path) {
		conf.Log.Path = filepath.Join(basePath, conf.Log.Path)
	}

	dirExists = utils.FileOrDirectoryExists(conf.Log.Path)

	if !dirExists {
		return &Config{}, errors.New(fmt.Sprintf("A log directory is missing. Please create it manually."))
	}

	return &conf, nil
}
