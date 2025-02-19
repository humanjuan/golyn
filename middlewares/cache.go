package middlewares

import (
	"Back/internal/utils"
	"github.com/gin-gonic/gin"
	"github.com/jpengineer/logger"
	"github.com/patrickmn/go-cache"
	"net/http"
)

func CacheMiddleware(log *logger.Log, servCache *cache.Cache) gin.HandlerFunc {
	log.Debug("cacheMiddleware()")
	return func(c *gin.Context) {
		c.Set("serverCache", servCache)
		c.Next()
	}
}

func GetCache(c *gin.Context) *cache.Cache {
	serverCache, ok := c.MustGet("serverCache").(*cache.Cache)

	if !ok {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{
			"error":   utils.GetCodeMessage(http.StatusInternalServerError),
			"message": "serverCache type mismatch",
		})
		return nil
	}
	return serverCache
}
