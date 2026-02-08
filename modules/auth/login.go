package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/humanjuan/golyn/config/loaders"
	"github.com/humanjuan/golyn/database"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/security"
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
		ip := c.ClientIP()
		userAgent := c.Request.UserAgent()

		// Multi-tenant Isolation Check
		if !user[0].IsGlobal {
			var currentSiteID string
			var siteResults []database.Site
			err = db.Select("SELECT id FROM core.sites WHERE lower(host) = lower($1)", &siteResults, siteID)
			if err == nil && len(siteResults) > 0 {
				currentSiteID = siteResults[0].Id
			}

			if currentSiteID == "" {
				log.Warn("Login() | Site not found: %s", siteID)
				c.Error(utils.NewHTTPError(http.StatusForbidden, "site not registered in Golyn"))
				c.Abort()
				return
			}

			// User is restricted to their original site OR allowed sites
			if user[0].SiteID == nil || *user[0].SiteID != currentSiteID {
				allowed, err := db.IsSiteAllowedForUser(user[0].Id, currentSiteID)
				if err != nil || !allowed {
					log.Warn("Login() | Access Denied (Isolation) | User: %s | Host: %s", effectiveUsername, siteID)
					c.Error(utils.NewHTTPError(http.StatusForbidden, "access denied for this site"))
					c.Abort()
					return
				}
			}
		}

		accessToken, refreshToken, err := CreateToken(effectiveUsername, siteID, ip, userAgent)
		if err != nil {
			log.Error("Login() | An error has occurred in the server when trying to get access tokens. Try again later: %s", err.Error())
			err = fmt.Errorf("an error has occurred in the server when trying to get access tokens")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			c.Abort()
			return
		}

		user[0].PasswordHash = ""

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
		c.SetCookie("refreshToken", refreshToken, expirationTimeSec, "/", config.Server.CookieDomain, config.Server.CookieSecure, config.Server.CookieHttpOnly)
		c.SetCookie("access_token", accessToken, accessTokenExpSec, "/", config.Server.CookieDomain, config.Server.CookieSecure, config.Server.CookieHttpOnly)

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
		}, c.ClientIP(), c.Request.UserAgent())
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
		c.SetCookie("refreshToken", newRefreshToken, expirationTimeSec, "/", config.Server.CookieDomain, config.Server.CookieSecure, config.Server.CookieHttpOnly)
		c.SetCookie("access_token", newAccessToken, accessTokenExpSec, "/", config.Server.CookieDomain, config.Server.CookieSecure, config.Server.CookieHttpOnly)

		c.Status(http.StatusNoContent)
	}
}

func Logout() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		config := globals.GetConfig()
		db := globals.GetDBInstance()

		// Check for SLO (global logout)
		globalLogout := c.Query("global") == "true"

		var providerHint string
		refreshToken, err := c.Cookie("refreshToken")
		if err == nil && refreshToken != "" {
			claims, err := ValidateRefreshToken(refreshToken)
			if err == nil {
				if globalLogout && claims.SessionID != 0 {
					extSession, err := db.GetExternalSessionBySessionID(claims.SessionID)
					if err == nil && extSession != nil {
						providerHint = extSession.Provider
						// Perform revocation/SLO based on provider
						log.Debug("Logout() | Initiating SLO for provider: %s | User: %s", extSession.Provider, claims.Subject)

						// Revoke provider tokens (Back-channel)
						err := RevokeProviderToken(extSession)
						if err != nil {
							log.Warn("Logout() | Failed to revoke provider token: %v", err)
						}

						// Handle Front-channel SLO if provider supports it
						sloURL := GetProviderLogoutURL(extSession)
						if sloURL != "" {
							clearLocalCookies(c, config)
							_ = db.RevokeRefreshTokenByID(claims.SessionID)

							log.Info("Logout() | Redirecting to provider SLO: %s", sloURL)
							c.Redirect(http.StatusTemporaryRedirect, sloURL)
							return
						}
					}
				}

				var users []struct {
					ID string `db:"id"`
				}
				err = db.Select("SELECT id FROM auth.users WHERE lower(username) = lower($1)", &users, claims.Subject)
				if err == nil && len(users) > 0 {
					_ = db.RevokeAllUserRefreshTokens(users[0].ID)
					log.Debug("Logout() | Revoked tokens for user: %s", claims.Subject)
				}

				if claims.SessionID != 0 && providerHint == "" {
					if extSession, er2 := db.GetExternalSessionBySessionID(claims.SessionID); er2 == nil && extSession != nil {
						providerHint = extSession.Provider
					}
				}
			}
		}

		clearLocalCookies(c, config)

		// If last provider was an external one and no global SLO requested, help UX by forcing account selection next time
		// This applies to Google, Azure, OIDC and others that support the 'prompt' parameter.
		if providerHint != "" && !globalLogout {
			c.SetSameSite(utils.StringToSameSite(config.Server.CookieSameSite))
			c.SetCookie("oauth_force_select_account", "1", 60, "/", config.Server.CookieDomain, config.Server.CookieSecure, config.Server.CookieHttpOnly)
			log.Info("Logout() | Set oauth_force_select_account helper cookie for next %s login", providerHint)
		}

		log.Info("Logout() | User logged out and cookies cleared | ClientIP: %s", c.ClientIP())

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Message: "Successfully logged out",
		})
	}
}

func clearLocalCookies(c *gin.Context, config *loaders.Config) {
	c.SetSameSite(utils.StringToSameSite(config.Server.CookieSameSite))
	c.SetCookie("refreshToken", "", -1, "/", config.Server.CookieDomain, config.Server.CookieSecure, config.Server.CookieHttpOnly)
	c.SetCookie("access_token", "", -1, "/", config.Server.CookieDomain, config.Server.CookieSecure, config.Server.CookieHttpOnly)

	c.SetCookie("oauth_state", "", -1, "/", config.Server.CookieDomain, config.Server.CookieSecure, config.Server.CookieHttpOnly)
	c.SetCookie("oauth_next", "", -1, "/", config.Server.CookieDomain, config.Server.CookieSecure, config.Server.CookieHttpOnly)
}

func RevokeProviderToken(session *database.ExternalSession) error {
	log := globals.GetAppLogger()
	accessToken, _ := security.DecryptPassword(session.AccessToken)
	refreshToken, _ := security.DecryptPassword(session.RefreshToken)

	log.Debug("RevokeProviderToken() | Provider: %s | HasAccessToken: %v | HasRefreshToken: %v", session.Provider, accessToken != "", refreshToken != "")

	switch session.Provider {
	case "google":
		token := refreshToken
		if token == "" {
			token = accessToken
		}
		if token == "" {
			return nil
		}
		resp, err := http.Post("https://oauth2.googleapis.com/revoke?token="+token, "application/x-www-form-urlencoded", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("google revocation failed: %s", resp.Status)
		}
		log.Info("RevokeProviderToken(google) | Back-channel revocation successful")

	case "github":
		conf := globals.GetConfig()
		provider, ok := conf.OAuth2.Providers["github"]
		if !ok || provider.ClientID == "" || provider.ClientSecret == "" {
			db := globals.GetDBInstance()
			dbProvider, err := db.GetAuthProviderBySlug("github")
			if err == nil && dbProvider != nil {
				if dbProvider.ClientID != nil {
					provider.ClientID = *dbProvider.ClientID
				}
				if dbProvider.ClientSecret != nil {
					provider.ClientSecret = *dbProvider.ClientSecret
				}
			}
		}

		if provider.ClientID == "" || provider.ClientSecret == "" {
			log.Warn("RevokeProviderToken(github) | Missing client_id or client_secret for revocation")
			return nil
		}

		token := accessToken
		if token == "" {
			return nil
		}

		url := fmt.Sprintf("https://api.github.com/applications/%s/token", provider.ClientID)
		reqBody := strings.NewReader(fmt.Sprintf(`{"access_token":"%s"}`, token))
		req, err := http.NewRequest(http.MethodDelete, url, reqBody)
		if err != nil {
			return err
		}
		req.SetBasicAuth(provider.ClientID, provider.ClientSecret)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
			return fmt.Errorf("github revocation failed: %s", resp.Status)
		}
		log.Info("RevokeProviderToken(github) | Back-channel revocation successful")

	case "facebook":
		if accessToken == "" {
			return nil
		}
		url := fmt.Sprintf("https://graph.facebook.com/me/permissions?access_token=%s", accessToken)
		req, err := http.NewRequest(http.MethodDelete, url, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("facebook revocation failed: %s", resp.Status)
		}
		log.Info("RevokeProviderToken(facebook) | Back-channel revocation successful")

	case "amazon":
		if accessToken == "" {
			return nil
		}
		conf := globals.GetConfig()
		provider := conf.OAuth2.Providers["amazon"]
		if provider.ClientID == "" {
			db := globals.GetDBInstance()
			dbP, _ := db.GetAuthProviderBySlug("amazon")
			if dbP != nil {
				if dbP.ClientID != nil {
					provider.ClientID = *dbP.ClientID
				}
				if dbP.ClientSecret != nil {
					provider.ClientSecret = *dbP.ClientSecret
				}
			}
		}

		params := fmt.Sprintf("token=%s&client_id=%s&client_secret=%s", accessToken, provider.ClientID, provider.ClientSecret)
		resp, err := http.Post("https://api.amazon.com/auth/o2/token/revoke", "application/x-www-form-urlencoded", strings.NewReader(params))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("amazon revocation failed: %s", resp.Status)
		}
		log.Info("RevokeProviderToken(amazon) | Back-channel revocation successful")

	case "salesforce":
		if accessToken == "" {
			return nil
		}
		resp, err := http.Post("https://login.salesforce.com/services/oauth2/revoke?token="+accessToken, "application/x-www-form-urlencoded", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("salesforce revocation failed: %s", resp.Status)
		}
		log.Info("RevokeProviderToken(salesforce) | Back-channel revocation successful")

	case "linkedin":
		if accessToken == "" {
			return nil
		}
		conf := globals.GetConfig()
		provider := conf.OAuth2.Providers["linkedin"]
		if provider.ClientID == "" {
			db := globals.GetDBInstance()
			dbP, _ := db.GetAuthProviderBySlug("linkedin")
			if dbP != nil {
				if dbP.ClientID != nil {
					provider.ClientID = *dbP.ClientID
				}
				if dbP.ClientSecret != nil {
					provider.ClientSecret = *dbP.ClientSecret
				}
			}
		}
		params := fmt.Sprintf("token=%s&client_id=%s&client_secret=%s", accessToken, provider.ClientID, provider.ClientSecret)
		resp, err := http.Post("https://www.linkedin.com/oauth/v2/revoke", "application/x-www-form-urlencoded", strings.NewReader(params))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("linkedin revocation failed: %s", resp.Status)
		}
		log.Info("RevokeProviderToken(linkedin) | Back-channel revocation successful")

	case "x":
		if accessToken == "" {
			return nil
		}
		conf := globals.GetConfig()
		provider := conf.OAuth2.Providers["x"]
		if provider.ClientID == "" {
			db := globals.GetDBInstance()
			dbP, _ := db.GetAuthProviderBySlug("x")
			if dbP != nil {
				if dbP.ClientID != nil {
					provider.ClientID = *dbP.ClientID
				}
				if dbP.ClientSecret != nil {
					provider.ClientSecret = *dbP.ClientSecret
				}
			}
		}
		params := fmt.Sprintf("token=%s&client_id=%s&client_secret=%s&token_type_hint=access_token", accessToken, provider.ClientID, provider.ClientSecret)
		req, err := http.NewRequest(http.MethodPost, "https://api.twitter.com/2/oauth2/revoke", strings.NewReader(params))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(provider.ClientID, provider.ClientSecret)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("x revocation failed: %s", resp.Status)
		}
		log.Info("RevokeProviderToken(x) | Back-channel revocation successful")

	default:
		log.Debug("RevokeProviderToken(%s) | Back-channel revocation not implemented or not required", session.Provider)
	}
	return nil
}

func GetProviderLogoutURL(session *database.ExternalSession) string {
	log := globals.GetAppLogger()
	idToken, _ := security.DecryptPassword(session.IDToken)

	config := globals.GetConfig()
	scheme := "https"
	if config.Server.Dev {
		scheme = "http"
	}
	postLogoutRedirect := fmt.Sprintf("%s://%s/", scheme, config.Server.MainDomain)

	log.Debug("GetProviderLogoutURL() | Provider: %s | HasIDToken: %v | Redirect: %s", session.Provider, idToken != "", postLogoutRedirect)

	switch session.Provider {
	case "azure":
		db := globals.GetDBInstance()
		tenant := "common"
		dbProvider, err := db.GetAuthProviderBySlug("azure")
		if err == nil && dbProvider != nil && dbProvider.TenantID != nil && *dbProvider.TenantID != "" {
			tenant = *dbProvider.TenantID
		}

		logoutURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/logout?post_logout_redirect_uri=%s", tenant, utils.URLEncode(postLogoutRedirect))
		if idToken != "" {
			logoutURL += "&id_token_hint=" + utils.URLEncode(idToken)
		}
		return logoutURL

	case "oidc":
		if idToken == "" {
			return ""
		}
		endSessionEndpoint := ""
		db := globals.GetDBInstance()
		dbProvider, _ := db.GetAuthProviderBySlug("oidc")
		if dbProvider != nil && dbProvider.Metadata != nil {
			var metadata map[string]interface{}
			if err := json.Unmarshal([]byte(*dbProvider.Metadata), &metadata); err == nil {
				if es, ok := metadata["end_session_endpoint"].(string); ok {
					endSessionEndpoint = es
				}
			}
		}

		if endSessionEndpoint != "" {
			return fmt.Sprintf("%s?id_token_hint=%s&post_logout_redirect_uri=%s",
				endSessionEndpoint, utils.URLEncode(idToken), utils.URLEncode(postLogoutRedirect))
		}
	}
	return ""
}

func ListPublicAuthProviders() gin.HandlerFunc {
	return func(c *gin.Context) {
		db := globals.GetDBInstance()
		providers, err := db.GetAuthProviders()
		if err != nil {
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "failed to get auth providers"))
			c.Abort()
			return
		}

		type PublicProviderDTO struct {
			Slug string `json:"slug"`
			Name string `json:"name"`
		}

		publicProviders := make([]PublicProviderDTO, 0)
		for _, p := range providers {
			if p.Enabled {
				publicProviders = append(publicProviders, PublicProviderDTO{
					Slug: p.Slug,
					Name: p.Name,
				})
			}
		}

		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Data:    publicProviders,
		})
	}
}
