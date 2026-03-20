package virtualhosts

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/app"
	"github.com/humanjuan/golyn/config/loaders"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/middlewares"
	"github.com/humanjuan/golyn/routes"
)

func Setup(router *gin.Engine) map[string][]app.VirtualHost {
	log := globals.GetAppLogger()
	log.Debug("Setup() | Configured virtual hosts")
	config := globals.GetConfig()
	virtualHosts := make(map[string][]app.VirtualHost)

	for _, siteConfig := range config.Sites {
		if !siteConfig.Enabled {
			log.Warn("Setup() | Site '%s' is disabled. | Skipping...", siteConfig.Directory)
			continue
		}

		// if proxy = true, apply reverse proxy
		if siteConfig.Proxy {
			log.Info("Setup() | Site '%s' is configured as reverse proxy for: %v", siteConfig.Directory, siteConfig.Domains)
		}

		// Determine the base path for this site
		basePath := filepath.Join(config.Server.SitesRootPath, siteConfig.Directory)

		if !siteConfig.Proxy {
			if _, err := os.Stat(basePath); os.IsNotExist(err) {
				log.Error("Setup() | Site directory does not exist | Path: %s", basePath)
				continue
			}
		}

		var siteGroup *gin.RouterGroup
		if !siteConfig.Proxy {
			// If path prefix is not root, use it as part of the group path
			groupPath := fmt.Sprintf("/%s", siteConfig.Directory)
			if siteConfig.PathPrefix != "/" {
				groupPath = siteConfig.PathPrefix
			}

			siteGroup = router.Group(groupPath)
			{
				// Secure static file routes
				siteGroup.GET("/style/*filepath", routes.CreateRouteHandler(siteConfig.StaticFiles.Style))
				siteGroup.GET("/js/*filepath", routes.CreateRouteHandler(siteConfig.StaticFiles.Js))
				siteGroup.GET("/assets/*filepath", routes.CreateRouteHandler(siteConfig.StaticFiles.Assets))

				// Serve the index file
				siteGroup.GET("/", routes.CreateStaticFileHandler(filepath.Join(basePath, "index.html")))

				// Serve favicon
				siteGroup.GET("/favicon.ico", routes.CreateStaticFileHandler(filepath.Join(siteConfig.StaticFiles.Assets, "favicon.ico")))

				// SEO
				siteGroup.GET("/robots.txt", routes.CreateStaticFileHandler(filepath.Join(basePath, "robots.txt")))
				siteGroup.GET("/sitemap.xml", routes.CreateStaticFileHandler(filepath.Join(basePath, "sitemap.xml")))
				siteGroup.GET("/humans.txt", routes.CreateStaticFileHandler(filepath.Join(basePath, "humans.txt")))

			}
		}

		// Asocia cada dominio con el `VirtualHost`
		for _, domain := range siteConfig.Domains {
			vh := app.VirtualHost{
				HostName:           domain,
				SiteName:           siteConfig.Directory,
				ConfigPath:         siteConfig.Path,
				BasePath:           basePath,
				SiteGroup:          siteGroup,
				Proxy:              siteConfig.Proxy,
				ProxyTarget:        siteConfig.ProxyTarget,
				ProxyFlushInterval: siteConfig.ProxyFlushInterval,
				PathPrefix:         siteConfig.PathPrefix,
				Security:           siteConfig.Security,
				SMTP:               siteConfig.SMTP,
			}
			virtualHosts[domain] = append(virtualHosts[domain], vh)
			log.Info("Setup() | Configured virtual host '%s%s' for site directory: %s",
				domain, siteConfig.PathPrefix, basePath)
		}
	}

	// Sort VirtualHosts for each domain by PathPrefix length descending (longest match first)
	for domain := range virtualHosts {
		sort.Slice(virtualHosts[domain], func(i, j int) bool {
			return len(virtualHosts[domain][i].PathPrefix) > len(virtualHosts[domain][j].PathPrefix)
		})
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
		hostParts := strings.Split(c.Request.Host, ":")
		host := hostParts[0]

		target, exists := proxyMap[host]
		log.Debug("CreateDynamicProxyHandler() | ProxyCheck | Host: %s | Path: %s | Exists: %v | Target: %s", host, c.Request.URL.Path, exists, target)

		if exists {
			log.Info("CreateDynamicProxyHandler() | Applying reverse proxy to %s", target)
			middleware := middlewares.ReverseProxyMiddleware(target)
			middleware(c)
			return
		}

		log.Debug("CreateDynamicProxyHandler() | Host not found in proxyMap: %s", host)
		c.Next()
	}
}
