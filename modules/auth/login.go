package auth

import (
	"Back/app"
	"Back/database"
	"Back/internal/utils"
	"Back/middlewares"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

func Login(app *app.Application) gin.HandlerFunc {
	return func(c *gin.Context) {
		_cache := middlewares.GetCache(c)
		log := app.LogApp
		logDB := app.LogDB
		loginUser := database.LoginUser{}

		if err := c.BindJSON(&loginUser); err != nil {
			log.Error("Login() | Invalid or unexpectedly formatted JSON provided in request body. %s", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{
				"message": utils.GetCodeMessage(http.StatusBadRequest),
				"error":   "Invalid or unexpectedly formatted JSON provided in request body",
			})
			return
		}

		db := app.DB
		var user []database.User

		var attempts = 0

		logDB.Debug("Login() | query: %v | args: %v", database.Queries["login"], loginUser.Name)
		err := db.Select(database.Queries["login"], &user, loginUser.Name)
		if err != nil {
			logDB.Error("Login() | An error has occurred in the database. Try again later: %s", err.Error())

			c.IndentedJSON(http.StatusInternalServerError, gin.H{
				"message": utils.GetCodeMessage(http.StatusInternalServerError),
				"error":   "An error has occurred in the database. Try again later.",
			})
			return
		}

		if user == nil || len(user) == 0 {
			// verify cache
			if attempt, found := _cache.Get(c.ClientIP()); found {
				attempts = attempt.(int)
				attempts++
				_cache.Set(c.ClientIP(), attempts, cache.DefaultExpiration)
			} else {
				attempts = 1
				_cache.Set(c.ClientIP(), attempts, cache.DefaultExpiration)
			}
			log.Error("Login() | ClientIP: %s | User: %s (Not Found)| Login: Failed | Attempts: %d | Sleep: 5s | Cache Items: %d",
				c.ClientIP(), loginUser.Name, attempts, _cache.ItemCount())
			time.Sleep(5 * time.Second)

			c.IndentedJSON(http.StatusUnauthorized, gin.H{
				"message": utils.GetCodeMessage(http.StatusUnauthorized),
				"error":   "Login failed",
			})
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(user[0].Password), []byte(loginUser.Password))

		if err != nil {
			// verify cache
			if attempt, found := _cache.Get(c.ClientIP()); found {
				attempts = attempt.(int)
				attempts++
				_cache.Set(c.ClientIP(), attempts, cache.DefaultExpiration)
			} else {
				attempts = 1
				_cache.Set(c.ClientIP(), attempts, cache.DefaultExpiration)
			}
			log.Error("Login() | ClientIP: %s | User: %s | Login: Failed | Attempts: %d | Sleep: 5s | Cache Items: %d",
				c.ClientIP(), loginUser.Name, attempts, _cache.ItemCount())
			time.Sleep(5 * time.Second)

			c.IndentedJSON(http.StatusUnauthorized, gin.H{
				"message": utils.GetCodeMessage(http.StatusUnauthorized),
				"error":   "Login failed",
			})
			return
		}

		if attempt, found := _cache.Get(c.ClientIP()); found {
			attempts = attempt.(int)
			attempts++
			_cache.Delete(c.ClientIP())
		} else {
			attempts = 1
		}

		log.Info("ClientIP: %s | User: %s | Login: Success | Attempts: %v | Sleep: 0s | Cache Items: %d",
			c.ClientIP(), loginUser.Name, attempts, _cache.ItemCount())

		accessToken, refreshToken, err := CreateToken(loginUser.Name, app)
		if err != nil {
			log.Error("Login() | An error has occurred in the server when trying to get access tokens. Try again later: %s", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": utils.GetCodeMessage(http.StatusInternalServerError),
				"error":   "An error has occurred in the server when trying to get access tokens"})
			return
		}

		user[0].Password = ""
		jsonUser, err := json.Marshal(user[0])
		if err != nil {
			log.Error("Login() | An error has occurred in the server when trying to build the final user object. Try again later: %s", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": utils.GetCodeMessage(http.StatusInternalServerError),
				"error":   "An error has occurred in the server when trying to build the final user object. Try again later.",
			})
			return
		}

		expirationTimeSec := app.Config.Server.TokenExpirationRefreshTime
		c.SetSameSite(http.SameSiteLaxMode)
		//domain := c.Request.Host
		c.SetCookie("refreshToken", refreshToken, expirationTimeSec, "/", "", true, true)
		c.IndentedJSON(http.StatusOK, gin.H{
			"message":      utils.GetCodeMessage(http.StatusOK),
			"data":         string(jsonUser),
			"access_token": accessToken,
		})
		return
	}
}

func RefreshToken(app *app.Application) gin.HandlerFunc {
	return func(c *gin.Context) {

		log := app.LogApp

		refreshToken, err := c.Cookie("refreshToken")
		if err != nil {
			log.Error("RefreshToken() | Refresh token not provided in cookie: %v", err.Error())
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Refresh token not provided in cookie",
				"error":   err.Error(),
			})
			return
		}

		claims, err := ValidateRefreshToken(refreshToken, app)
		if err != nil {
			log.Error("RefreshToken() | Invalid or expired refresh token: %v", err.Error())
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Invalid or expired refresh token",
				"error":   err.Error(),
			})
			return
		}

		newAccessToken, newRefreshToken, err := IssueNewTokens(refreshToken, jwt.MapClaims{
			"username": claims.Username,
			"exp":      time.Now().Add(time.Duration(app.Config.Server.TokenExpirationTime) * time.Minute).Unix(),
		}, app)
		if err != nil {
			log.Error("RefreshToken() | Unable to issue new tokens, try again: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "Unable to issue new tokens, try again",
				"error":   err.Error(),
			})
			return
		}

		expirationTimeSec := app.Config.Server.TokenExpirationRefreshTime * 60
		c.SetSameSite(http.SameSiteLaxMode)
		//domain := c.Request.Host
		c.SetCookie("refreshToken", newRefreshToken, expirationTimeSec, "/", "", true, true)

		c.JSON(http.StatusOK, gin.H{
			"access_token": newAccessToken,
		})
	}
}
