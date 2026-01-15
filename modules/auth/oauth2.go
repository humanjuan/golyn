package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/database"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
)

// ProviderUserInfo defines a common structure for user info across providers
type ProviderUserInfo struct {
	ID    string
	Email string
	Name  string
	Raw   interface{}
}

func getOAuth2Config(providerName string) (*oauth2.Config, error) {
	conf := globals.GetConfig()
	provider, ok := conf.OAuth2.Providers[providerName]
	if !ok || !provider.Enabled {
		return nil, fmt.Errorf("%s OAuth2 is disabled or not configured", providerName)
	}

	var endpoint oauth2.Endpoint
	switch providerName {
	case "azure":
		endpoint = microsoft.AzureADEndpoint(provider.TenantID)
	case "google":
		endpoint = google.Endpoint
	case "github":
		endpoint = github.Endpoint
	default:
		return nil, fmt.Errorf("unsupported provider: %s", providerName)
	}

	scopes := []string{"openid", "profile", "email"}
	if providerName == "azure" {
		scopes = append(scopes, "User.Read")
	}

	return &oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		RedirectURL:  provider.RedirectURL,
		Endpoint:     endpoint,
		Scopes:       scopes,
	}, nil
}

func OAuth2Login(provider string) gin.HandlerFunc {
	return func(c *gin.Context) {
		oauthConfig, err := getOAuth2Config(provider)
		if err != nil {
			c.Error(utils.NewHTTPError(http.StatusForbidden, err.Error()))
			c.Abort()
			return
		}

		// Implement secure state management (CSRF)
		state := utils.GenerateRandomString(32)
		c.SetCookie("oauth_state", state, 300, "/api/v1/auth", "", !globals.GetConfig().Server.Dev, true)

		// Support for dynamic redirection after login
		next := c.Query("next")
		if next != "" {
			c.SetCookie("oauth_next", next, 300, "/api/v1/auth", "", !globals.GetConfig().Server.Dev, true)
		}

		url := oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
		c.Redirect(http.StatusTemporaryRedirect, url)
	}
}

func OAuth2Callback(provider string) gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		config := globals.GetConfig()

		oauthConfig, err := getOAuth2Config(provider)
		if err != nil {
			c.Error(utils.NewHTTPError(http.StatusForbidden, err.Error()))
			c.Abort()
			return
		}

		state := c.Query("state")
		cookieState, err := c.Cookie("oauth_state")
		if err != nil || state != cookieState {
			log.Error("OAuth2Callback(%s) | Invalid or missing state", provider)
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "Invalid or missing CSRF state"))
			c.Abort()
			return
		}
		c.SetCookie("oauth_state", "", -1, "/api/v1/auth", "", !config.Server.Dev, true)

		code := c.Query("code")
		if code == "" {
			log.Error("OAuth2Callback(%s) | Missing code", provider)
			c.Error(utils.NewHTTPError(http.StatusBadRequest, "Missing authorization code"))
			c.Abort()
			return
		}

		token, err := oauthConfig.Exchange(context.Background(), code)
		if err != nil {
			log.Error("OAuth2Callback(%s) | Code exchange failed: %v", provider, err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "Failed to exchange token"))
			c.Abort()
			return
		}

		userInfo, err := fetchUserInfo(provider, oauthConfig, token)
		if err != nil {
			log.Error("OAuth2Callback(%s) | Failed to fetch user info: %v", provider, err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "Failed to fetch user info from provider"))
			c.Abort()
			return
		}

		log.Debug("OAuth2Callback(%s) | Fetched user info: ID=%s, Email=%s", provider, userInfo.ID, userInfo.Email)

		db := globals.GetDBInstance()

		extIdentity, err := db.GetExternalIdentity(provider, userInfo.ID)
		var user *database.User

		if err == nil && extIdentity != nil {
			var users []database.User
			err = db.Select("SELECT id, site_id, username, status FROM auth.users WHERE id = $1", &users, extIdentity.UserId)
			if err == nil && len(users) > 0 {
				user = &users[0]
				// Update metadata and email if they changed
				metadata, _ := json.Marshal(userInfo.Raw)
				err = db.LinkExternalIdentity(user.Id, provider, userInfo.ID, userInfo.Email, metadata)
				if err != nil {
					log.Error("OAuth2Callback(%s) | Failed to update external identity metadata: %v", provider, err)
				}
			}
		}

		if user == nil {
			log.Debug("OAuth2Callback(%s) | Searching user by email: %s", provider, userInfo.Email)
			userByEmail, err := db.GetUserByEmail(userInfo.Email)
			if err == nil && userByEmail != nil {
				log.Debug("OAuth2Callback(%s) | Found user by email: %s (ID: %s)", provider, userByEmail.Username, userByEmail.Id)
				user = userByEmail
				metadata, _ := json.Marshal(userInfo.Raw)
				err = db.LinkExternalIdentity(user.Id, provider, userInfo.ID, userInfo.Email, metadata)
				if err != nil {
					log.Error("OAuth2Callback(%s) | Failed to link external identity: %v", provider, err)
				}
			} else {
				log.Warn("OAuth2Callback(%s) | User not found by email: %s | Error: %v", provider, userInfo.Email, err)
			}
		}

		if user == nil {
			log.Warn("OAuth2Callback(%s) | User not found: %s", provider, userInfo.Email)
			c.Error(utils.NewHTTPError(http.StatusUnauthorized, "User not registered in Golyn platform"))
			c.Abort()
			return
		}

		if user.Status != "active" {
			log.Warn("OAuth2Callback(%s) | User is inactive: %s", provider, userInfo.Email)
			c.Error(utils.NewHTTPError(http.StatusForbidden, "User account is inactive"))
			c.Abort()
			return
		}

		siteID := c.Request.Host
		accessToken, refreshToken, err := CreateToken(user.Username, siteID)
		if err != nil {
			log.Error("OAuth2Callback(%s) | Token creation failed: %v", provider, err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "Failed to create access tokens"))
			c.Abort()
			return
		}

		ip := c.ClientIP()
		userAgent := c.Request.UserAgent()
		event := fmt.Sprintf("oauth2_login_%s", provider)
		var siteUUID *string
		var siteResults []database.Site
		err = db.Select("SELECT id FROM core.sites WHERE lower(host) = lower($1)", &siteResults, siteID)
		if err == nil && len(siteResults) > 0 {
			siteUUID = &siteResults[0].Id
		}

		err = db.RegisterAuthEvent(&user.Id, siteUUID, event, ip, userAgent)
		if err != nil {
			log.Error("OAuth2Callback(%s) | Failed to register auth event: %v", provider, err)
		}

		expirationTimeSec := config.Server.TokenExpirationRefreshTime * 60
		accessTokenExpSec := config.Server.TokenExpirationTime * 60

		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie("refreshToken", refreshToken, expirationTimeSec, "/", "", !config.Server.Dev, true)
		c.SetCookie("access_token", accessToken, accessTokenExpSec, "/", "", !config.Server.Dev, true)

		next, err := c.Cookie("oauth_next")
		if err == nil && next != "" {
			c.SetCookie("oauth_next", "", -1, "/api/v1/auth", "", !config.Server.Dev, true)
			c.Redirect(http.StatusTemporaryRedirect, next)
			return
		}

		response := BuildLoginResponse(*user, provider)
		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Data:    response,
		})
	}
}

func fetchUserInfo(provider string, config *oauth2.Config, token *oauth2.Token) (*ProviderUserInfo, error) {
	client := config.Client(context.Background(), token)

	switch provider {
	case "azure":
		resp, err := client.Get("https://graph.microsoft.com/v1.0/me")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var azureUser struct {
			ID                string `json:"id"`
			UserPrincipalName string `json:"userPrincipalName"`
			Mail              string `json:"mail"`
			DisplayName       string `json:"displayName"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&azureUser); err != nil {
			return nil, err
		}
		email := azureUser.Mail
		if email == "" {
			email = azureUser.UserPrincipalName
		}
		return &ProviderUserInfo{
			ID:    azureUser.ID,
			Email: email,
			Name:  azureUser.DisplayName,
			Raw:   azureUser,
		}, nil

	case "google":
		resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var googleUser struct {
			ID    string `json:"id"`
			Email string `json:"email"`
			Name  string `json:"name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
			return nil, err
		}
		return &ProviderUserInfo{
			ID:    googleUser.ID,
			Email: googleUser.Email,
			Name:  googleUser.Name,
			Raw:   googleUser,
		}, nil

	case "github":
		resp, err := client.Get("https://api.github.com/user")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var githubUser struct {
			ID    int    `json:"id"`
			Login string `json:"login"`
			Email string `json:"email"`
			Name  string `json:"name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&githubUser); err != nil {
			return nil, err
		}

		if githubUser.Email == "" {
			emailResp, err := client.Get("https://api.github.com/user/emails")
			if err == nil {
				defer emailResp.Body.Close()
				var emails []struct {
					Email    string `json:"email"`
					Primary  bool   `json:"primary"`
					Verified bool   `json:"verified"`
				}
				if err := json.NewDecoder(emailResp.Body).Decode(&emails); err == nil {
					for _, e := range emails {
						if e.Primary && e.Verified {
							githubUser.Email = e.Email
							break
						}
					}
				}
			}
		}

		return &ProviderUserInfo{
			ID:    fmt.Sprintf("%d", githubUser.ID),
			Email: githubUser.Email,
			Name:  githubUser.Name,
			Raw:   githubUser,
		}, nil

	default:
		return nil, fmt.Errorf("user info fetch not implemented for %s", provider)
	}
}
