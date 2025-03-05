package middlewares

import (
	"Back/globals"
	"Back/internal/utils"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"net/http"
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
	serverCache, ok := c.MustGet("serverCache").(*cache.Cache)
	if !ok {
		log.Error("GetCache() | serverCache type mismatch")
		err := fmt.Errorf("serverCache type mismatch")
		c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
		c.Abort()
		return nil
	}
	return serverCache
}
