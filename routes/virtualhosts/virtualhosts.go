package virtualhosts

import (
	"Back/app"
	"Back/config/loaders"
	"Back/globals"
	"Back/middlewares"
	"Back/routes"
	"fmt"
	"github.com/gin-gonic/gin"
	"os"
	"path/filepath"
)

func Setup(router *gin.Engine) map[string]app.VirtualHost {
	log := globals.GetAppLogger()
	log.Debug("Setup() | Configured virtual hosts")
	config := globals.GetConfig()
	virtualHosts := make(map[string]app.VirtualHost)

	for _, siteConfig := range config.Sites {
		if !siteConfig.Enabled {
			log.Warn("Setup() | Site '%s' is disabled. | Skipping...", siteConfig.Directory)
			continue
		}

		// if proxy = true, apply reverse proxy
		if siteConfig.Proxy {
			log.Info("Setup() | Site '%s' is configured as reverse proxy for: %v", siteConfig.Directory, siteConfig.Domains)
			continue
		}

		// Determine the base path for this site
		basePath := filepath.Join(config.Server.SitesRootPath, siteConfig.Directory)

		if _, err := os.Stat(basePath); os.IsNotExist(err) {
			log.Error("Setup() | Site directory does not exist | Path: %s", basePath)
			continue
		}

		siteGroup := router.Group(fmt.Sprintf("/%s", siteConfig.Directory))
		{
			// Secure static file routes
			siteGroup.GET("/style/*filepath", routes.CreateRouteHandler(siteConfig.StaticFiles.Style, "style"))
			siteGroup.GET("/js/*filepath", routes.CreateRouteHandler(siteConfig.StaticFiles.Js, "js"))
			siteGroup.GET("/assets/*filepath", routes.CreateRouteHandler(siteConfig.StaticFiles.Assets, "assets"))

			// Serve the index file
			siteGroup.GET("/", routes.CreateStaticFileHandler(filepath.Join(basePath, "index.html")))

			// Serve favicon
			siteGroup.GET("/favicon.ico", routes.CreateStaticFileHandler(filepath.Join(siteConfig.StaticFiles.Assets, "favicon.ico")))
		}

		// Asocia cada dominio con el `VirtualHost`
		for _, domain := range siteConfig.Domains {
			virtualHosts[domain] = app.VirtualHost{
				HostName:    domain,
				BasePath:    basePath,
				SiteGroup:   siteGroup,
				Proxy:       siteConfig.Proxy,
				ProxyTarget: siteConfig.ProxyTarget,
				Security:    siteConfig.Security,
				SMTP:        siteConfig.SMTP,
			}
			log.Info("Setup() | Configured virtual host '%s' for site directory: %s", domain, basePath)
		}
	}

	globals.DefaultSite = "./sites/golyn"

	log.Info("Setup() | Default Site Path: %s", globals.DefaultSite)
	return virtualHosts
}

func BuildProxyHostMap(sites []loaders.SiteConfig) map[string]string {
	log := globals.GetAppLogger()
	log.Debug("BuildProxyHostMap()")
	proxyMap := make(map[string]string)

	for _, site := range sites {
		if site.Proxy {
			for _, domain := range site.Domains {
				proxyMap[domain] = site.ProxyTarget
			}
		}
	}
	return proxyMap
}

func CreateDynamicProxyHandler(proxyMap map[string]string) gin.HandlerFunc {
	log := globals.GetAppLogger()
	log.Debug("CreateDynamicProxyHandler()")
	return func(c *gin.Context) {
		host := c.Request.Host
		target, exists := proxyMap[host]
		log.Debug("CreateDynamicProxyHandler() | ProxyCheck | Host: %s | Path: %s | Exists: %v | Target: %s", host, c.Request.URL.Path, exists, target)

		if exists {
			log.Info("CreateDynamicProxyHandler() | Applying reverse proxy to %s", target)
			middleware := middlewares.ReverseProxyMiddleware(target)
			middleware(c)
			return
		}

		log.Warn("CreateDynamicProxyHandler() | Host not found in proxyMap: %s", host)
		c.Next()
	}
}
