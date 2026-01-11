package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/database"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
)

// GetMe returns the current authenticated user's profile
func GetMe() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		log.Debug("GetMe()")

		// Extract subject (username) from context, set by AuthMiddleware
		subject, exists := c.Get("subject")
		if !exists {
			log.Error("GetMe() | Subject not found in context")
			c.Error(utils.NewHTTPError(http.StatusUnauthorized, "User not authenticated"))
			c.Abort()
			return
		}

		username := subject.(string)

		db := globals.GetDBInstance()
		var users []database.User
		query := database.Queries["get_user_by_username"]

		err := db.Select(query, &users, username)
		if err != nil {
			log.Error("GetMe() | Error fetching user from DB | Error: %v", err.Error())
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "Internal server error"))
			c.Abort()
			return
		}

		if len(users) == 0 {
			log.Warn("GetMe() | User not found in DB | Username: %s", username)
			c.Error(utils.NewHTTPError(http.StatusNotFound, "User not found"))
			c.Abort()
			return
		}

		user := users[0]

		// Return user profile safely (excluding sensitive data like PasswordHash)
		c.JSON(http.StatusOK, gin.H{
			"id":         user.Id,
			"site_id":    user.SiteID,
			"username":   user.Username,
			"role":       user.Role,
			"status":     user.Status,
			"created_at": user.CreatedAt,
			"updated_at": user.UpdatedAt,
		})
	}
}
