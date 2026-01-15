package user

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/database"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
)

type ThemeConfig struct {
	Sidebar     map[string]string `json:"sidebar"`
	LogoVariant string            `json:"logoVariant"`
}

func GetTheme() gin.HandlerFunc {
	return func(c *gin.Context) {
		username, exists := c.Get("subject")
		if !exists {
			c.Error(utils.NewHTTPError(http.StatusUnauthorized, "User not authenticated"))
			c.Abort()
			return
		}

		db := globals.GetDBInstance()
		var themes []struct {
			Theme []byte `db:"theme"`
		}
		query := database.Queries["get_user_theme"]
		err := db.Select(query, &themes, username)

		if err != nil || len(themes) == 0 {
			c.JSON(http.StatusOK, utils.APIResponse{Success: true, Data: nil})
			return
		}

		if themes[0].Theme == nil {
			c.JSON(http.StatusOK, utils.APIResponse{Success: true, Data: nil})
			return
		}

		var theme ThemeConfig
		if err := json.Unmarshal(themes[0].Theme, &theme); err != nil {
			c.JSON(http.StatusOK, utils.APIResponse{Success: true, Data: nil})
			return
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Data:    theme,
		})
	}
}

func UpdateTheme() gin.HandlerFunc {
	return func(c *gin.Context) {
		username, exists := c.Get("subject")
		if !exists {
			c.Error(utils.NewHTTPError(http.StatusUnauthorized, "User not authenticated"))
			c.Abort()
			return
		}

		var newTheme ThemeConfig
		if err := c.ShouldBindJSON(&newTheme); err != nil {
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "Invalid theme data"))
			c.Abort()
			return
		}

		// Validation
		if newTheme.LogoVariant != "white" && newTheme.LogoVariant != "black" {
			newTheme.LogoVariant = "white"
		}

		themeJSON, err := json.Marshal(newTheme)
		if err != nil {
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "Failed to process theme data"))
			c.Abort()
			return
		}

		db := globals.GetDBInstance()
		query := database.Queries["update_user_theme"]
		_, err = db.GetPool().Exec(c.Request.Context(), query, themeJSON, username)

		if err != nil {
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "Failed to save theme preferences"))
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Message: "Theme updated successfully",
			Data:    newTheme,
		})
	}
}
