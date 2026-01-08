package admin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/database"
	"github.com/humanjuan/golyn/globals"
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
		err := db.CreateSite(req.Key, req.Host)
		if err != nil {
			log.Error("Admin.CreateSite() | Failed to create site: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to create site"))
			c.Abort()
			return
		}

		c.JSON(http.StatusCreated, gin.H{"message": "site created successfully"})
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
		c.JSON(http.StatusOK, sites)
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
		site, err := db.GetSiteByKey(req.SiteKey)
		if err != nil || site == nil {
			c.Error(utils.NewHTTPError(http.StatusNotFound, "site not found"))
			c.Abort()
			return
		}

		if req.Role == "" {
			req.Role = "user"
		}

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
		err = db.CreateUser(site.Id, req.Username, string(hashedPassword), req.Role)
		if err != nil {
			log.Error("Admin.CreateUser() | Failed to create user: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to create user"))
			c.Abort()
			return
		}

		c.JSON(http.StatusCreated, gin.H{"message": "user created successfully"})
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

		// Clear password hashes from response
		for i := range users {
			users[i].PasswordHash = ""
		}

		c.JSON(http.StatusOK, users)
	}
}
