package admin

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/database"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/security/hierarchy"
	"github.com/humanjuan/golyn/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

type CreateSiteRequest struct {
	Key  string `json:"key" binding:"required"`
	Host string `json:"host" binding:"required"`
}

type CreateUserRequest struct {
	SiteKey  string `json:"site_key" binding:"required"`
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Role     string `json:"role"`
}

func CreateSite() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		var req CreateSiteRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "invalid request body"))
			c.Abort()
			return
		}

		db := globals.GetDBInstance()
		req.Key = strings.ToLower(req.Key)
		req.Host = strings.ToLower(req.Host)
		err := db.CreateSite(req.Key, req.Host)
		if err != nil {
			log.Error("Admin.CreateSite() | Failed to create site: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to create site"))
			c.Abort()
			return
		}

		c.JSON(http.StatusCreated, utils.APIResponse{
			Success: true,
			Message: "site created successfully",
		})
	}
}

func ListSites() gin.HandlerFunc {
	return func(c *gin.Context) {
		db := globals.GetDBInstance()
		sites, err := db.GetAllSites()
		if err != nil {
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to list sites"))
			c.Abort()
			return
		}

		dtos := make([]SiteDTO, len(sites))
		for i, s := range sites {
			dtos[i] = MapSiteToDTO(s)
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Data:    dtos,
		})
	}
}

func DeleteSite() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		key := strings.ToLower(c.Param("key"))
		if key == "" {
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "site key is required"))
			c.Abort()
			return
		}

		db := globals.GetDBInstance()
		err := db.DeleteSite(key)
		if err != nil {
			log.Error("Admin.DeleteSite() | Failed to delete site: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to delete site"))
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Message: "site deleted successfully",
		})
	}
}

type UpdateSiteStatusRequest struct {
	Status string `json:"status" binding:"required"`
}

func UpdateSiteStatus() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		key := strings.ToLower(c.Param("key"))
		if key == "" {
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "site key is required"))
			c.Abort()
			return
		}

		var req UpdateSiteStatusRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "invalid request body"))
			c.Abort()
			return
		}

		db := globals.GetDBInstance()
		req.Status = strings.ToLower(req.Status)
		err := db.UpdateSiteStatus(key, req.Status)
		if err != nil {
			log.Error("Admin.UpdateSiteStatus() | Failed to update site status: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to update site status"))
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Message: "site status updated successfully",
		})
	}
}

func CreateUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		var req CreateUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "invalid request body"))
			c.Abort()
			return
		}

		db := globals.GetDBInstance()
		req.SiteKey = strings.ToLower(req.SiteKey)
		req.Username = strings.ToLower(req.Username)
		req.Role = strings.ToLower(req.Role)
		site, err := db.GetSiteByKey(req.SiteKey)
		if err != nil || site == nil {
			c.Error(utils.NewHTTPError(http.StatusNotFound, "site not found"))
			c.Abort()
			return
		}

		if req.Role == "" {
			req.Role = "user"
		}

		// Role Hierarchy Check
		actorRoleVal, _ := c.Get("role")
		actorRole := strings.ToLower(fmt.Sprintf("%v", actorRoleVal))
		if !hierarchy.CanCreate(actorRole, req.Role) {
			log.Warn("Admin.CreateUser() | Hierarchy Violation | Actor: %s (%s) tried to create: %s", c.GetString("subject"), actorRole, req.Role)
			c.Error(utils.NewHTTPError(http.StatusForbidden, "hierarchy violation: cannot create user with higher or equal role"))
			c.Abort()
			return
		}

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
		err = db.CreateUser(site.Id, req.Username, string(hashedPassword), req.Role)
		if err != nil {
			log.Error("Admin.CreateUser() | Failed to create user: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to create user"))
			c.Abort()
			return
		}

		c.JSON(http.StatusCreated, utils.APIResponse{
			Success: true,
			Message: "user created successfully",
		})
	}
}

func ListUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		siteKey := c.Query("site_key")
		db := globals.GetDBInstance()

		var users []database.User
		var err error

		if siteKey != "" {
			site, err := db.GetSiteByKey(siteKey)
			if err != nil || site == nil {
				c.Error(utils.NewHTTPError(http.StatusNotFound, "site not found"))
				c.Abort()
				return
			}
			users, err = db.GetUsersBySite(site.Id)
		} else {
			users, err = db.GetAllUsers()
		}

		if err != nil {
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to list users"))
			c.Abort()
			return
		}

		dtos := make([]AdminUserDTO, len(users))
		for i, u := range users {
			dtos[i] = MapAdminUserToDTO(u)
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Data:    dtos,
		})
	}
}

func DeleteUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		username := strings.ToLower(c.Param("username"))
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
			log.Warn("Admin.DeleteUser() | Hierarchy Violation | Actor: %s (%s) tried to delete: %s (%s)", c.GetString("subject"), actorRole, username, targetUser.Role)
			c.Error(utils.NewHTTPError(http.StatusForbidden, "hierarchy violation: cannot delete user with higher or equal role"))
			c.Abort()
			return
		}

		err = db.DeleteUser(username)
		if err != nil {
			log.Error("Admin.DeleteUser() | Failed to delete user: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to delete user"))
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Message: "user deleted successfully",
		})
	}
}

func UpdateUserStatus() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		username := strings.ToLower(c.Param("username"))
		if username == "" {
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "username is required"))
			c.Abort()
			return
		}

		var req struct {
			Status string `json:"status" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "invalid request body"))
			c.Abort()
			return
		}

		// Basic validation of status
		validStatus := map[string]bool{"active": true, "inactive": true, "pending": true}
		if !validStatus[req.Status] {
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "invalid status value"))
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
			log.Warn("Admin.UpdateUserStatus() | Hierarchy Violation | Actor: %s (%s) tried to update status: %s (%s)", c.GetString("subject"), actorRole, username, targetUser.Role)
			c.Error(utils.NewHTTPError(http.StatusForbidden, "hierarchy violation: cannot update status for user with higher or equal role"))
			c.Abort()
			return
		}

		err = db.UpdateUserStatus(username, req.Status)
		if err != nil {
			log.Error("Admin.UpdateUserStatus() | Failed to update user status: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to update user status"))
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Message: "user status updated successfully",
		})
	}
}

func UpdateUserRole() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		actorRoleVal, _ := c.Get("role")
		actorRole := strings.ToLower(fmt.Sprintf("%v", actorRoleVal))

		username := strings.ToLower(c.Param("username"))
		if username == "" {
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "username is required"))
			c.Abort()
			return
		}

		var req struct {
			Role string `json:"role" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "invalid request body"))
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

		if !hierarchy.CanManage(actorRole, targetUser.Role) {
			log.Warn("Admin.UpdateUserRole() | Hierarchy Violation | Actor: %s (%s) tried to update role: %s (%s)", c.GetString("subject"), actorRole, username, targetUser.Role)
			c.Error(utils.NewHTTPError(http.StatusForbidden, "hierarchy violation: cannot update role for user with higher or equal role"))
			c.Abort()
			return
		}

		// Check if the NEW role is allowed to be assigned by actor
		if !hierarchy.CanCreate(actorRole, req.Role) {
			log.Warn("Admin.UpdateUserRole() | Hierarchy Violation | Actor: %s (%s) tried to assign role: %s", c.GetString("subject"), actorRole, req.Role)
			c.Error(utils.NewHTTPError(http.StatusForbidden, "hierarchy violation: cannot assign a role higher or equal to yours"))
			c.Abort()
			return
		}

		err = db.UpdateUserRole(username, req.Role)
		if err != nil {
			log.Error("Admin.UpdateUserRole() | Failed to update user role: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to update user role"))
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Message: "user role updated successfully",
		})
	}
}
