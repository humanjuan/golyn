package lifecycle

import (
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/globals"
)

type RouterHook interface {
	OnRouterReady(router *gin.RouterGroup)
}

func NotifyRouterReady(router *gin.Engine) {
	log := globals.GetAppLogger()

	if log != nil {
		log.Info("NotifyRouterReady() | lifecycle | router ready")
	}

	for i, rh := range hooks {
		ra, ok := rh.hook.(RouterHook)
		if !ok {
			continue
		}

		if log != nil {
			log.Debug("NotifyRouterReady() | notifying hook | index=%d | id=%s | type=%T", i+1, rh.id, rh.hook)
		}

		// Aislamiento de Rutas: Prefijo Protegido /api/v1/extension/{id}/
		prefix := "/api/v1/extension/" + rh.id
		group := router.Group(prefix)

		ra.OnRouterReady(group)
	}
}
