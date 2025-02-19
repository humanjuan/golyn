package virtualhosts

import (
	"Back/app"
	"Back/config/loaders"
	"Back/routes"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/jpengineer/logger"
	"os"
	"path/filepath"
)

func Setup(router *gin.Engine, config *loaders.Config, log *logger.Log) (map[string]app.VirtualHost, string) {
	log.Debug("Setup() | Configured virtual hosts")
	var defaultSitePath string
	virtualHosts := make(map[string]app.VirtualHost)
	processedDirectories := make(map[string]*gin.RouterGroup)

	for _, siteConfig := range config.Sites {
		if !siteConfig.Enabled {
			log.Warn("Site '%s' is disabled. Skipping...", siteConfig.Directory)
			continue
		}

		// Determine the base path for this site
		basePath := filepath.Join(config.Server.SitesRootPath, siteConfig.Directory)

		if _, err := os.Stat(basePath); os.IsNotExist(err) {
			log.Error("Site directory does not exist: %s", basePath)
			continue
		}

		siteGroup := router.Group(fmt.Sprintf("/%s", siteConfig.Directory))
		{
			// Secure static file routes
			siteGroup.GET("/style/*filepath", routes.CreateRouteHandler(siteConfig.StaticFiles.Style, "style", log))
			siteGroup.GET("/js/*filepath", routes.CreateRouteHandler(siteConfig.StaticFiles.Js, "js", log))
			siteGroup.GET("/assets/*filepath", routes.CreateRouteHandler(siteConfig.StaticFiles.Assets, "assets", log))

			// Serve the index file
			siteGroup.GET("/", routes.CreateStaticFileHandler(filepath.Join(basePath, "index.html"), log))

			// Serve favicon
			siteGroup.GET("/favicon.ico", routes.CreateStaticFileHandler(filepath.Join(siteConfig.StaticFiles.Assets, "favicon.ico"), log))
		}

		// Asocia cada dominio con el `VirtualHost`
		for _, domain := range siteConfig.Domains {
			virtualHosts[domain] = app.VirtualHost{
				HostName:  domain,
				BasePath:  basePath,
				SiteGroup: processedDirectories[siteConfig.Directory],
			}
			log.Info("Configured virtual host '%s' for site directory: %s", domain, basePath)
		}
	}

	defaultSitePath = "./sites/golyn"

	log.Info("Default Site Path: %s", defaultSitePath)
	return virtualHosts, defaultSitePath
}
