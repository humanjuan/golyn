package virtualhosts

import (
	"Back/app"
	"Back/globals"
	"Back/middlewares"
	"Back/routes"
	"fmt"
	"github.com/gin-gonic/gin"
	"os"
	"path/filepath"
)

func Setup(router *gin.Engine) (map[string]app.VirtualHost, string) {
	log := globals.GetAppLogger()
	log.Debug("Setup() | Configured virtual hosts")
	config := globals.GetConfig()
	var defaultSitePath string
	var siteGroup *gin.RouterGroup
	virtualHosts := make(map[string]app.VirtualHost)
	// processedDirectories := make(map[string]*gin.RouterGroup)

	for _, siteConfig := range config.Sites {
		if !siteConfig.Enabled {
			log.Warn("Setup() | Site '%s' is disabled. | Skipping...", siteConfig.Directory)
			continue
		}

		// if proxy = true, apply reverse proxy
		if siteConfig.Proxy {
			siteGroup = router.Group(fmt.Sprintf("%s", siteConfig.Directory))
			siteGroup.Use(middlewares.ReverseProxyMiddleware(siteConfig.ProxyTarget))
			log.Info("Setup() | Configured proxy for site '%s' | Proxy Target: %s", siteConfig.Directory, siteConfig.ProxyTarget)
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
				HostName: domain,
				BasePath: basePath,
				// SiteGroup: processedDirectories[siteConfig.Directory],
				SiteGroup: siteGroup,
			}
			log.Info("Setup() | Configured virtual host '%s' for site directory: %s", domain, basePath)
		}
	}

	defaultSitePath = "./sites/golyn"

	log.Info("Setup() | Default Site Path: %s", defaultSitePath)
	return virtualHosts, defaultSitePath
}
