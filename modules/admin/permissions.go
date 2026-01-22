package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/security/hierarchy"
	"github.com/humanjuan/golyn/internal/utils"
)

type UserPermissions struct {
	Grants []string `json:"grants"`
	Denies []string `json:"denies"`
}

type UpdatePermissionsRequest struct {
	Permissions UserPermissions `json:"permissions" binding:"required"`
}

func GetUserPermissions() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		username := c.Param("username")
		if username == "" {
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "username is required"))
			c.Abort()
			return
		}

		db := globals.GetDBInstance()

		// Role Hierarchy Check
		targetUser, err := db.GetUserByUsername(username)
		if err != nil || targetUser == nil {
			c.Error(utils.NewHTTPError(http.StatusNotFound, "user not found"))
			c.Abort()
			return
		}

		actorRoleVal, _ := c.Get("role")
		actorRole := strings.ToLower(fmt.Sprintf("%v", actorRoleVal))
		if !hierarchy.CanManage(actorRole, targetUser.Role) {
			log.Warn("Admin.GetUserPermissions() | Hierarchy Violation | Actor: %s (%s) tried to view permissions: %s (%s)", c.GetString("subject"), actorRole, username, targetUser.Role)
			c.Error(utils.NewHTTPError(http.StatusForbidden, "hierarchy violation: cannot view permissions for user with higher or equal role"))
			c.Abort()
			return
		}

		permissionsRaw, err := db.GetUserPermissions(username)
		if err != nil {
			log.Error("Admin.GetUserPermissions() | Failed to fetch permissions: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to fetch permissions"))
			c.Abort()
			return
		}

		var permissions UserPermissions
		if permissionsRaw != nil {
			if err := json.Unmarshal(permissionsRaw, &permissions); err != nil {
				log.Error("Admin.GetUserPermissions() | Failed to unmarshal permissions: %v", err)
				// Fallback to empty
				permissions = UserPermissions{Grants: []string{}, Denies: []string{}}
			}
		} else {
			permissions = UserPermissions{Grants: []string{}, Denies: []string{}}
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Data:    permissions,
		})
	}
}

func UpdateUserPermissions() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		username := c.Param("username")
		if username == "" {
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "username is required"))
			c.Abort()
			return
		}

		var req UpdatePermissionsRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "invalid request body"))
			c.Abort()
			return
		}

		permissionsJSON, err := json.Marshal(req.Permissions)
		if err != nil {
			log.Error("Admin.UpdateUserPermissions() | Failed to marshal permissions: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to process permissions"))
			c.Abort()
			return
		}

		db := globals.GetDBInstance()

		// Role Hierarchy Check
		targetUser, err := db.GetUserByUsername(username)
		if err != nil || targetUser == nil {
			c.Error(utils.NewHTTPError(http.StatusNotFound, "user not found"))
			c.Abort()
			return
		}

		actorRoleVal, _ := c.Get("role")
		actorRole := strings.ToLower(fmt.Sprintf("%v", actorRoleVal))
		if !hierarchy.CanManage(actorRole, targetUser.Role) {
			log.Warn("Admin.UpdateUserPermissions() | Hierarchy Violation | Actor: %s (%s) tried to update permissions: %s (%s)", c.GetString("subject"), actorRole, username, targetUser.Role)
			c.Error(utils.NewHTTPError(http.StatusForbidden, "hierarchy violation: cannot update permissions for user with higher or equal role"))
			c.Abort()
			return
		}

		err = db.UpdateUserPermissions(username, permissionsJSON)
		if err != nil {
			log.Error("Admin.UpdateUserPermissions() | Failed to update permissions: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to update permissions"))
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Message: "Permissions updated successfully",
			Data:    req.Permissions,
		})
	}
}

func GetPermissionsCatalog() gin.HandlerFunc {
	return func(c *gin.Context) {
		catalog := map[string]interface{}{
			"Users": []map[string]string{
				{"key": "users.view", "label": "View"},
				{"key": "users.create", "label": "Create"},
				{"key": "users.update", "label": "Edit"},
				{"key": "users.delete", "label": "Delete"},
				{"key": "users.manage", "label": "Manage"},
			},
			"Sites": []map[string]string{
				{"key": "sites.view", "label": "View"},
				{"key": "sites.create", "label": "Create"},
				{"key": "sites.update", "label": "Edit"},
				{"key": "sites.delete", "label": "Delete"},
			},
			"System": []map[string]string{
				{"key": "system.logs", "label": "View Logs"},
				{"key": "system.stats", "label": "View Stats"},
				{"key": "system.info", "label": "View Info"},
			},
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Data:    catalog,
		})
	}
}
