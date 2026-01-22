package auth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/humanjuan/golyn/database"
	"github.com/humanjuan/golyn/globals"
	platjwt "github.com/humanjuan/golyn/internal/security/jwt"
	"github.com/humanjuan/golyn/internal/utils"
	"github.com/humanjuan/golyn/middlewares"
	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/bcrypt"
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

		effectiveUsername := strings.ToLower(loginUser.Username)
		if effectiveUsername == "" {
			effectiveUsername = strings.ToLower(loginUser.Name)
		}

		db := globals.GetDBInstance()
		var user []database.User

		var attempts = 0

		logDB.Debug("Login() | query: %v | args: %v", database.Queries["login"], effectiveUsername)
		err := db.Select(database.Queries["login"], &user, effectiveUsername)
		if err != nil {
			logDB.Error("Login() | An error has occurred in the database. Try again later: %s", err.Error())
			err = fmt.Errorf("an error has occurred in the database. Try again later")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			c.Abort()
			return
		}

		if user == nil || len(user) == 0 {
			if attempt, found := _cache.Get(c.ClientIP()); found {
				attempts = attempt.(int)
				attempts++
				_cache.Set(c.ClientIP(), attempts, cache.DefaultExpiration)
			} else {
				attempts = 1
				_cache.Set(c.ClientIP(), attempts, cache.DefaultExpiration)
			}
			log.Warn("Login() | ClientIP: %s | User: %s (Not Found)| Login: Failed | Attempts: %d | Sleep: 5s | Cache Items: %d",
				c.ClientIP(), effectiveUsername, attempts, _cache.ItemCount())
			time.Sleep(5 * time.Second)

			err = fmt.Errorf("login failed")
			c.Error(utils.NewHTTPError(http.StatusUnauthorized, err.Error()))
			c.Abort()
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(user[0].PasswordHash), []byte(loginUser.Password))

		if err != nil {
			if attempt, found := _cache.Get(c.ClientIP()); found {
				attempts = attempt.(int)
				attempts++
				_cache.Set(c.ClientIP(), attempts, cache.DefaultExpiration)
			} else {
				attempts = 1
				_cache.Set(c.ClientIP(), attempts, cache.DefaultExpiration)
			}
			log.Error("Login() | ClientIP: %s | User: %s | Login: Failed | Attempts: %d | Sleep: 5s | Cache Items: %d",
				c.ClientIP(), effectiveUsername, attempts, _cache.ItemCount())
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
			c.ClientIP(), effectiveUsername, attempts, _cache.ItemCount())

		siteID := c.Request.Host
		accessToken, refreshToken, err := CreateToken(effectiveUsername, siteID)
		if err != nil {
			log.Error("Login() | An error has occurred in the server when trying to get access tokens. Try again later: %s", err.Error())
			err = fmt.Errorf("an error has occurred in the server when trying to get access tokens")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			c.Abort()
			return
		}

		user[0].PasswordHash = ""

		ip := c.ClientIP()
		userAgent := c.Request.UserAgent()
		var siteUUID *string
		var siteResults []database.Site
		err = db.Select("SELECT id FROM core.sites WHERE lower(host) = lower($1)", &siteResults, siteID)
		if err == nil && len(siteResults) > 0 {
			siteUUID = &siteResults[0].Id
		}
		_ = db.RegisterAuthEvent(&user[0].Id, siteUUID, "local_login", ip, userAgent)

		expirationTimeSec := config.Server.TokenExpirationRefreshTime * 60
		accessTokenExpSec := config.Server.TokenExpirationTime * 60

		c.SetSameSite(utils.StringToSameSite(config.Server.CookieSameSite))
		c.SetCookie("refreshToken", refreshToken, expirationTimeSec, "/", "", config.Server.CookieSecure, config.Server.CookieHttpOnly)
		c.SetCookie("access_token", accessToken, accessTokenExpSec, "/", "", config.Server.CookieSecure, config.Server.CookieHttpOnly)

		response := BuildLoginResponse(
			user[0],
			"",
		)
		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Data:    response,
		})
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

		newAccessToken, newRefreshToken, err := IssueNewTokens(refreshToken, &platjwt.Claims{
			SiteID: claims.SiteID,
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   claims.Subject,
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(config.Server.TokenExpirationTime) * time.Minute)),
			},
		})
		if err != nil {
			log.Error("RefreshToken() | Unable to issue new tokens. Try again: %v", err)
			err = fmt.Errorf("unable to issue new tokens")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			c.Abort()
			return
		}

		expirationTimeSec := config.Server.TokenExpirationRefreshTime * 60
		accessTokenExpSec := config.Server.TokenExpirationTime * 60

		c.SetSameSite(utils.StringToSameSite(config.Server.CookieSameSite))
		c.SetCookie("refreshToken", newRefreshToken, expirationTimeSec, "/", "", config.Server.CookieSecure, config.Server.CookieHttpOnly)
		c.SetCookie("access_token", newAccessToken, accessTokenExpSec, "/", "", config.Server.CookieSecure, config.Server.CookieHttpOnly)

		c.Status(http.StatusNoContent)
	}
}

func Logout() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		config := globals.GetConfig()
		db := globals.GetDBInstance()

		refreshToken, err := c.Cookie("refreshToken")
		if err == nil && refreshToken != "" {
			claims, err := ValidateRefreshToken(refreshToken)
			if err == nil {
				var users []struct {
					ID string `db:"id"`
				}
				err = db.Select("SELECT id FROM auth.users WHERE lower(username) = lower($1)", &users, claims.Subject)
				if err == nil && len(users) > 0 {
					_ = db.RevokeAllUserRefreshTokens(users[0].ID)
					log.Debug("Logout() | Revoked tokens for user: %s", claims.Subject)
				}
			}
		}

		c.SetSameSite(utils.StringToSameSite(config.Server.CookieSameSite))
		c.SetCookie("refreshToken", "", -1, "/", "", config.Server.CookieSecure, config.Server.CookieHttpOnly)
		c.SetCookie("access_token", "", -1, "/", "", config.Server.CookieSecure, config.Server.CookieHttpOnly)

		c.SetCookie("oauth_state", "", -1, "/api/v1/auth", "", config.Server.CookieSecure, config.Server.CookieHttpOnly)
		c.SetCookie("oauth_next", "", -1, "/api/v1/auth", "", config.Server.CookieSecure, config.Server.CookieHttpOnly)

		log.Info("Logout() | User logged out and cookies cleared | ClientIP: %s", c.ClientIP())

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Message: "Successfully logged out",
		})
	}
}
