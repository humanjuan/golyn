package middlewares

import (
	"Back/globals"
	"Back/internal/utils"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"net/http"
	"path/filepath"
)

func CacheMiddleware(servCache *cache.Cache) gin.HandlerFunc {
	log := globals.GetAppLogger()
	log.Debug("cacheMiddleware()")
	return func(c *gin.Context) {
		c.Set("serverCache", servCache)
		c.Next()
	}
}

func GetCache(c *gin.Context) *cache.Cache {
	log := globals.GetAppLogger()
	log.Debug("GetCache()")
	servCache, ok := c.MustGet("serverCache").(*cache.Cache)
	if !ok {
		log.Error("GetCache() | serverCache type mismatch")
		err := fmt.Errorf("serverCache type mismatch")
		c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
		c.Abort()
		return nil
	}
	return servCache
}

func FileExistsCached(c *gin.Context, site string, relativePath string, encoding string) bool {
	log := globals.GetAppLogger()
	log.Debug("FileExistsCached()")
	servCache := GetCache(c)

	if servCache == nil {
		log.Error("FileExistsCached() | serverCache is nil")
		return false
	}

	key := buildCacheKey(site, relativePath, encoding)
	value, found := servCache.Get(key)
	if found {
		exists, ok := value.(bool)
		if ok {
			return exists
		}
	}

	virtualHosts := globals.VirtualHosts
	host := c.Request.Host
	virtualHost, ok := virtualHosts[host]
	if !ok {
		return false
	}

	fullPath := filepath.Join(virtualHost.BasePath, relativePath)

	if encoding == "br" || encoding == "gzip" || encoding == "zstd" || encoding == "deflate" {
		fullPath += "." + encoding
	}

	exists := utils.FileOrDirectoryExists(fullPath)
	servCache.SetDefault(key, exists)

	return exists

}

func buildCacheKey(site string, path string, encoding string) string {
	return fmt.Sprintf("%s:%s:%s", site, path, encoding)
}
