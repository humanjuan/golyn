package auth

import (
	"Back/database"
	"Back/globals"
	"Back/internal/utils"
	"Back/middlewares"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		_cache := middlewares.GetCache(c)
		log := globals.GetAppLogger()
		logDB := globals.GetDBLogger()
		config := globals.GetConfig()
		loginUser := database.LoginUser{}

		if err := c.BindJSON(&loginUser); err != nil {
			log.Error("Login() | Invalid or unexpectedly formatted JSON provided in request body. %s", err.Error())
			err = fmt.Errorf("invalid or unexpectedly formatted JSON provided in request body")
			c.Error(utils.NewHTTPError(http.StatusBadRequest, err.Error()))
			c.Abort()
			return
		}

		db := globals.GetDBInstance()
		var user []database.User

		var attempts = 0

		logDB.Debug("Login() | query: %v | args: %v", database.Queries["login"], loginUser.Name)
		err := db.Select(database.Queries["login"], &user, loginUser.Name)
		if err != nil {
			logDB.Error("Login() | An error has occurred in the database. Try again later: %s", err.Error())
			err = fmt.Errorf("an error has occurred in the database. Try again later")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			c.Abort()
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
			log.Warn("Login() | ClientIP: %s | User: %s (Not Found)| Login: Failed | Attempts: %d | Sleep: 5s | Cache Items: %d",
				c.ClientIP(), loginUser.Name, attempts, _cache.ItemCount())
			time.Sleep(5 * time.Second)

			err = fmt.Errorf("login failed")
			c.Error(utils.NewHTTPError(http.StatusUnauthorized, err.Error()))
			c.Abort()
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

			err = fmt.Errorf("login failed")
			c.Error(utils.NewHTTPError(http.StatusUnauthorized, err.Error()))
			c.Abort()
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

		accessToken, refreshToken, err := CreateToken(loginUser.Name)
		if err != nil {
			log.Error("Login() | An error has occurred in the server when trying to get access tokens. Try again later: %s", err.Error())
			err = fmt.Errorf("an error has occurred in the server when trying to get access tokens")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			c.Abort()
			return
		}

		user[0].Password = ""
		jsonUser, err := json.Marshal(user[0])
		if err != nil {
			log.Error("Login() | An error has occurred in the server when trying to build the final user object. Try again later: %s", err.Error())
			err = fmt.Errorf("an error has occurred in the server when trying to build the final user object")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			c.Abort()
			return
		}

		expirationTimeSec := config.Server.TokenExpirationRefreshTime
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

func RefreshToken() gin.HandlerFunc {
	return func(c *gin.Context) {

		log := globals.GetAppLogger()
		config := globals.GetConfig()

		refreshToken, err := c.Cookie("refreshToken")
		if err != nil {
			log.Error("RefreshToken() | Refresh token not provided in cookie: %v", err.Error())
			err = fmt.Errorf("refresh token not provided in cookie")
			c.Error(utils.NewHTTPError(http.StatusUnauthorized, err.Error()))
			c.Abort()
			return
		}

		claims, err := ValidateRefreshToken(refreshToken)
		if err != nil {
			log.Error("RefreshToken() | Invalid or expired refresh token: %v", err.Error())
			err = fmt.Errorf(" Invalid or expired refresh token")
			c.Error(utils.NewHTTPError(http.StatusUnauthorized, err.Error()))
			c.Abort()
			return
		}

		newAccessToken, newRefreshToken, err := IssueNewTokens(refreshToken, jwt.MapClaims{
			"username": claims.Username,
			"exp":      time.Now().Add(time.Duration(config.Server.TokenExpirationTime) * time.Minute).Unix(),
		})
		if err != nil {
			log.Error("RefreshToken() | Unable to issue new tokens. Try again: %v", err)
			err = fmt.Errorf("unable to issue new tokens")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			c.Abort()
			return
		}

		expirationTimeSec := config.Server.TokenExpirationRefreshTime * 60
		c.SetSameSite(http.SameSiteLaxMode)
		//domain := c.Request.Host
		c.SetCookie("refreshToken", newRefreshToken, expirationTimeSec, "/", "", true, true)

		c.JSON(http.StatusOK, gin.H{
			"access_token": newAccessToken,
		})
	}
}
