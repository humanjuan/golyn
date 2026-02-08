package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/humanjuan/acacia/v2"
	"github.com/humanjuan/golyn/database"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/security"
	platjwt "github.com/humanjuan/golyn/internal/security/jwt"
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
	db := globals.GetDBInstance()
	conf := globals.GetConfig()

	dbProvider, err := db.GetAuthProviderBySlug(providerName)
	var clientID, clientSecret, redirectURL, tenantID string
	var enabled bool

	// Load file provider for potential field-level fallback
	fileProvider, fileOk := conf.OAuth2.Providers[providerName]

	if err == nil && dbProvider != nil {
		enabled = dbProvider.Enabled
		if dbProvider.ClientID != nil {
			clientID = *dbProvider.ClientID
		}
		if dbProvider.ClientSecret != nil {
			clientSecret = *dbProvider.ClientSecret
		}
		if dbProvider.RedirectURL != nil {
			redirectURL = *dbProvider.RedirectURL
		}
		if dbProvider.TenantID != nil {
			tenantID = *dbProvider.TenantID
		}

		// Field merge fallback from file config when DB fields are empty
		if fileOk {
			if clientID == "" {
				clientID = fileProvider.ClientID
			}
			if clientSecret == "" {
				clientSecret = fileProvider.ClientSecret
			}
			if redirectURL == "" {
				redirectURL = fileProvider.RedirectURL
			}
			if tenantID == "" {
				tenantID = fileProvider.TenantID
			}
		}
	} else if fileOk {
		enabled = fileProvider.Enabled
		clientID = fileProvider.ClientID
		clientSecret = fileProvider.ClientSecret
		redirectURL = fileProvider.RedirectURL
		tenantID = fileProvider.TenantID
	} else {
		return nil, fmt.Errorf("%s OAuth2 is not configured", providerName)
	}

	if !enabled {
		return nil, fmt.Errorf("%s OAuth2 is disabled", providerName)
	}

	// Validate mandatory fields
	if clientID == "" || clientSecret == "" || redirectURL == "" {
		return nil, fmt.Errorf("%s OAuth2 is misconfigured: missing client_id/client_secret/redirect_url", providerName)
	}

	var endpoint oauth2.Endpoint
	switch providerName {
	case "azure":
		endpoint = microsoft.AzureADEndpoint(tenantID)
	case "google":
		endpoint = google.Endpoint
	case "github":
		endpoint = github.Endpoint
	case "linkedin":
		endpoint = oauth2.Endpoint{
			AuthURL:  "https://www.linkedin.com/oauth/v2/authorization",
			TokenURL: "https://www.linkedin.com/oauth/v2/accessToken",
		}
	case "facebook":
		endpoint = oauth2.Endpoint{
			AuthURL:  "https://www.facebook.com/v18.0/dialog/oauth",
			TokenURL: "https://graph.facebook.com/v18.0/oauth/access_token",
		}
	case "amazon":
		endpoint = oauth2.Endpoint{
			AuthURL:  "https://www.amazon.com/ap/oa",
			TokenURL: "https://api.amazon.com/auth/o2/token",
		}
	case "salesforce":
		endpoint = oauth2.Endpoint{
			AuthURL:  "https://login.salesforce.com/services/oauth2/authorize",
			TokenURL: "https://login.salesforce.com/services/oauth2/token",
		}
	case "apple":
		endpoint = oauth2.Endpoint{
			AuthURL:  "https://appleid.apple.com/auth/authorize",
			TokenURL: "https://appleid.apple.com/auth/token",
		}
	case "x":
		endpoint = oauth2.Endpoint{
			AuthURL:  "https://twitter.com/i/oauth2/authorize",
			TokenURL: "https://api.twitter.com/2/oauth2/token",
		}
	case "oidc":
		// For OIDC, we usually need discovery, but for a simple implementation
		// we can expect endpoints in metadata or use specific fields.
		endpoint = oauth2.Endpoint{}
		// If dbProvider exists, we can look for endpoints in Metadata
		if dbProvider != nil && dbProvider.Metadata != nil {
			var metadata map[string]interface{}
			if err := json.Unmarshal([]byte(*dbProvider.Metadata), &metadata); err == nil {
				if authURL, ok := metadata["auth_url"].(string); ok {
					endpoint.AuthURL = authURL
				}
				if tokenURL, ok := metadata["token_url"].(string); ok {
					endpoint.TokenURL = tokenURL
				}
			}
		}
	default:
		return nil, fmt.Errorf("unsupported provider: %s", providerName)
	}

	scopes := []string{"openid", "profile", "email"}
	if providerName == "azure" {
		scopes = append(scopes, "User.Read")
	} else if providerName == "github" {
		scopes = []string{"read:user", "user:email"}
	} else if providerName == "amazon" {
		scopes = []string{"profile"}
	} else if providerName == "facebook" {
		scopes = []string{"public_profile", "email"}
	} else if providerName == "apple" {
		scopes = []string{"name", "email"}
	} else if providerName == "x" {
		scopes = []string{"users.read", "users.email", "tweet.read", "offline.access"}
	}

	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
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
		log := globals.GetAppLogger()
		log.Debug("OAuth2Login(%s) | Setting oauth_state: %s | Host: %s", provider, state, c.Request.Host)
		cfg := globals.GetConfig()
		c.SetSameSite(utils.StringToSameSite(cfg.Server.CookieSameSite))
		c.SetCookie("oauth_state", state, 300, "/", cfg.Server.CookieDomain, cfg.Server.CookieSecure, cfg.Server.CookieHttpOnly)

		// Support for dynamic redirection after login
		next := c.Query("next")
		if next != "" {
			c.SetCookie("oauth_next", next, 300, "/", cfg.Server.CookieDomain, cfg.Server.CookieSecure, cfg.Server.CookieHttpOnly)
		}

		// Building provider-specific options
		opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}

		// ---- PKCE REQUIRED FOR X ----
		if provider == "x" {
			verifier := utils.GenerateRandomString(64)
			challenge := utils.SHA256Base64URL(verifier)

			c.SetCookie(
				"oauth_pkce_verifier",
				verifier,
				300,
				"/",
				cfg.Server.CookieDomain,
				cfg.Server.CookieSecure,
				cfg.Server.CookieHttpOnly,
			)

			opts = append(opts,
				oauth2.SetAuthURLParam("code_challenge", challenge),
				oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			)

			log.Debug("OAuth2Login(%s) | PKCE enabled", provider)
		}

		// Allow callers to pass arbitrary prompt value via query (e.g., prompt=consent)
		promptParam := c.Query("prompt")
		if promptParam != "" {
			opts = append(opts, oauth2.SetAuthURLParam("prompt", promptParam))
		}

		// Force account selection when requested (helps after local logout)
		// Supported by Google, Azure, and most OIDC providers
		forceSelect := c.Query("force_select_account") == "true"
		if !forceSelect {
			if v, err := c.Cookie("oauth_force_select_account"); err == nil && v == "1" {
				forceSelect = true
				// clear the helper cookie
				c.SetCookie("oauth_force_select_account", "", -1, "/", cfg.Server.CookieDomain, cfg.Server.CookieSecure, cfg.Server.CookieHttpOnly)
			}
		}

		if forceSelect && promptParam == "" { // don't override explicit prompt
			// Most providers (Google, Microsoft, OIDC) use 'prompt=select_account'
			// GitHub does not support a standard prompt parameter for account switching in the same way,
			// it usually relies on browser session or explicit logout from github.com.
			if !strings.EqualFold(provider, "github") {
				opts = append(opts, oauth2.SetAuthURLParam("prompt", "select_account"))
				log.Debug("OAuth2Login(%s) | Applying prompt=select_account (force)", provider)
			}
		}

		url := oauthConfig.AuthCodeURL(state, opts...)
		c.Redirect(http.StatusTemporaryRedirect, url)
	}
}

func handleAuthError(c *gin.Context, log *acacia.Log, provider string, status int, message string, err error) {
	if err != nil {
		log.Error("OAuth2Callback(%s) | %s: %v", provider, message, err)
	} else {
		log.Warn("OAuth2Callback(%s) | %s", provider, message)
	}

	// Try to get origin site from next cookie if available, or use current host
	redirectBase := ""
	next, _ := c.Cookie("oauth_next")
	if next != "" {
		// Basic parsing to get the origin domain
		if strings.HasPrefix(next, "http") {
			parts := strings.Split(next, "/")
			if len(parts) >= 3 {
				redirectBase = parts[0] + "//" + parts[2]
			}
		}
	}

	if redirectBase == "" {
		scheme := "https"
		if globals.GetConfig().Server.Dev {
			scheme = "http"
		}
		redirectBase = fmt.Sprintf("%s://%s", scheme, c.Request.Host)
	}

	// Clean up next cookie
	config := globals.GetConfig()
	c.SetCookie("oauth_next", "", -1, "/", config.Server.CookieDomain, config.Server.CookieSecure, config.Server.CookieHttpOnly)

	errorURL := fmt.Sprintf("%s/login?error=%s", redirectBase, utils.URLEncode(message))
	c.Redirect(http.StatusTemporaryRedirect, errorURL)
}

func OAuth2Callback(provider string) gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		config := globals.GetConfig()

		oauthConfig, err := getOAuth2Config(provider)
		if err != nil {
			handleAuthError(c, log, provider, http.StatusForbidden, err.Error(), nil)
			c.Abort()
			return
		}

		state := c.Query("state")
		cookieState, err := c.Cookie("oauth_state")
		if err != nil || state != cookieState {
			msg := "Invalid or missing CSRF state"
			log.Error("OAuth2Callback(%s) | %s | QueryState: %s | CookieState: %s | Error: %v", provider, msg, state, cookieState, err)
			handleAuthError(c, log, provider, http.StatusBadRequest, msg, nil)
			c.Abort()
			return
		}
		c.SetSameSite(utils.StringToSameSite(config.Server.CookieSameSite))
		c.SetCookie("oauth_state", "", -1, "/", config.Server.CookieDomain, config.Server.CookieSecure, config.Server.CookieHttpOnly)

		code := c.Query("code")
		if code == "" {
			msg := "Missing authorization code"
			handleAuthError(c, log, provider, http.StatusBadRequest, msg, nil)
			c.Abort()
			return
		}

		var token *oauth2.Token

		if provider == "x" {
			verifier, err := c.Cookie("oauth_pkce_verifier")
			if err != nil {
				handleAuthError(c, log, provider, http.StatusBadRequest, "missing pkce verifier", err)
				return
			}

			token, err = oauthConfig.Exchange(
				context.Background(),
				code,
				oauth2.SetAuthURLParam("code_verifier", verifier),
			)

			// cleanup
			c.SetCookie("oauth_pkce_verifier", "", -1, "/", config.Server.CookieDomain, config.Server.CookieSecure, config.Server.CookieHttpOnly)
		} else {
			token, err = oauthConfig.Exchange(context.Background(), code)
		}

		if err != nil {
			handleAuthError(c, log, provider, http.StatusInternalServerError, "Failed to exchange token", err)
			return
		}

		userInfo, err := fetchUserInfo(provider, oauthConfig, token)
		if err != nil {
			handleAuthError(c, log, provider, http.StatusInternalServerError, "Failed to fetch user info from provider", err)
			c.Abort()
			return
		}

		log.Debug("OAuth2Callback(%s) | Fetched user info: ID=%s, Email=%s", provider, userInfo.ID, userInfo.Email)

		db := globals.GetDBInstance()

		extIdentity, err := db.GetExternalIdentity(provider, userInfo.ID)
		var user *database.User

		if err == nil && extIdentity != nil {
			var users []database.User
			err = db.Select("SELECT id, site_id, username, role, status, is_global, is_external FROM auth.users WHERE id = $1", &users, extIdentity.UserId)
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
			if userInfo.Email != "" {
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
		}

		if user == nil {
			handleAuthError(c, log, provider, http.StatusUnauthorized, "User not registered in Golyn platform", nil)
			c.Abort()
			return
		}

		if user.Status != "active" {
			handleAuthError(c, log, provider, http.StatusForbidden, "User account is inactive", nil)
			c.Abort()
			return
		}

		siteID := c.Request.Host
		ip := c.ClientIP()
		userAgent := c.Request.UserAgent()

		// Multi-tenant Isolation Check
		if !user.IsGlobal {
			var currentSiteID string
			var siteResults []database.Site
			err = db.Select("SELECT id FROM core.sites WHERE lower(host) = lower($1)", &siteResults, siteID)
			if err == nil && len(siteResults) > 0 {
				currentSiteID = siteResults[0].Id
			}

			if currentSiteID == "" {
				handleAuthError(c, log, provider, http.StatusForbidden, "site not registered in Golyn", nil)
				c.Abort()
				return
			}

			// User is restricted to their original site OR allowed sites
			if user.SiteID == nil || *user.SiteID != currentSiteID {
				allowed, err := db.IsSiteAllowedForUser(user.Id, currentSiteID)
				if err != nil || !allowed {
					handleAuthError(c, log, provider, http.StatusForbidden, "access denied for this site", nil)
					c.Abort()
					return
				}
			}
		}

		accessToken, refreshToken, err := CreateToken(user.Username, siteID, ip, userAgent)
		if err != nil {
			log.Error("OAuth2Callback(%s) | Token creation failed: %v", provider, err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, "Failed to create access tokens"))
			c.Abort()
			return
		}

		// Persist external provider tokens securely, linked to the Golyn session
		var sessionID int64
		claims := &platjwt.Claims{}
		parsed, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
			return platjwt.GetJWTKey(), nil
		})
		if err == nil && parsed != nil && parsed.Valid {
			sessionID = claims.SessionID
		}

		if sessionID != 0 {
			// Extract provider tokens
			provAccess := token.AccessToken
			provRefresh := token.RefreshToken
			provIDToken := ""
			if rawID := token.Extra("id_token"); rawID != nil {
				provIDToken = fmt.Sprintf("%v", rawID)
			}

			encAccess := ""
			encRefresh := ""
			encID := ""
			var encErr error
			if provAccess != "" {
				encAccess, encErr = security.EncryptPassword(provAccess)
				if encErr != nil {
					log.Warn("OAuth2Callback(%s) | Failed to encrypt provider access token: %v", provider, encErr)
				}
			}
			if provRefresh != "" {
				encRefresh, encErr = security.EncryptPassword(provRefresh)
				if encErr != nil {
					log.Warn("OAuth2Callback(%s) | Failed to encrypt provider refresh token: %v", provider, encErr)
				}
			}
			if provIDToken != "" {
				encID, encErr = security.EncryptPassword(provIDToken)
				if encErr != nil {
					log.Warn("OAuth2Callback(%s) | Failed to encrypt provider id_token: %v", provider, encErr)
				}
			}

			if encAccess != "" || encRefresh != "" || encID != "" {
				if err := db.StoreExternalSession(sessionID, provider, userInfo.ID, encAccess, encRefresh, encID, &token.Expiry); err != nil {
					log.Error("OAuth2Callback(%s) | Failed to store external session: %v", provider, err)
				}
			}
		}

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

		c.SetSameSite(utils.StringToSameSite(config.Server.CookieSameSite))
		c.SetCookie("refreshToken", refreshToken, expirationTimeSec, "/", config.Server.CookieDomain, config.Server.CookieSecure, config.Server.CookieHttpOnly)
		c.SetCookie("access_token", accessToken, accessTokenExpSec, "/", config.Server.CookieDomain, config.Server.CookieSecure, config.Server.CookieHttpOnly)

		next, err := c.Cookie("oauth_next")
		if err == nil && next != "" {
			c.SetCookie("oauth_next", "", -1, "/", config.Server.CookieDomain, config.Server.CookieSecure, config.Server.CookieHttpOnly)
			c.Redirect(http.StatusTemporaryRedirect, next)
			return
		}

		// If no next cookie, redirect to root or dashboard
		// This fixes the issue where the user sees a JSON response after login
		scheme := "https"
		if config.Server.Dev {
			scheme = "http"
		}
		defaultRedirect := fmt.Sprintf("%s://%s/", scheme, c.Request.Host)
		c.Redirect(http.StatusTemporaryRedirect, defaultRedirect)
	}
}

func fetchUserInfo(provider string, config *oauth2.Config, token *oauth2.Token) (*ProviderUserInfo, error) {
	client := config.Client(context.Background(), token)
	log := globals.GetAppLogger()

	switch provider {
	case "azure":
		resp, err := client.Get("https://graph.microsoft.com/v1.0/me")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read Azure response body: %v", err)
		}
		log.Debug("OAuth2Login(%s) | Azure Graph /me status: %d", provider, resp.StatusCode)
		log.Debug("OAuth2Login(%s) | Azure Graph /me raw body: %s", provider, string(bodyBytes))

		var azureUser struct {
			ID                string `json:"id"`
			UserPrincipalName string `json:"userPrincipalName"`
			Mail              string `json:"mail"`
			DisplayName       string `json:"displayName"`
		}
		if err := json.Unmarshal(bodyBytes, &azureUser); err != nil {
			return nil, err
		}
		// Microsoft Entra ID doesn't return a simple "email_verified" field in Graph API /me
		// but usually UserPrincipalName/Mail are verified if they are from the tenant.
		// For extra security in multi-tenant apps, one should check the 'id_token'.
		// However, for standard usage we assume these are verified.
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

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read Google response body: %v", err)
		}
		log.Debug("OAuth2Login(%s) | Google /users/me status: %d", provider, resp.StatusCode)
		log.Debug("OAuth2Login(%s) | Google /users/me raw body: %s", provider, string(bodyBytes))

		var googleUser struct {
			ID            string `json:"id"`
			Email         string `json:"email"`
			VerifiedEmail bool   `json:"verified_email"`
			Name          string `json:"name"`
		}
		if err := json.Unmarshal(bodyBytes, &googleUser); err != nil {
			return nil, err
		}
		if !googleUser.VerifiedEmail {
			return nil, fmt.Errorf("google email not verified")
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

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read GitHub response body: %v", err)
		}
		log.Debug("OAuth2Login(%s) | GitHub /users/me status: %d", provider, resp.StatusCode)
		log.Debug("OAuth2Login(%s) | GitHub /users/me raw body: %s", provider, string(bodyBytes))

		var githubUser struct {
			ID    int    `json:"id"`
			Login string `json:"login"`
			Email string `json:"email"`
			Name  string `json:"name"`
		}
		if err := json.Unmarshal(bodyBytes, &githubUser); err != nil {
			return nil, err
		}

		// Force primary and verified email
		githubUser.Email = ""
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

		if githubUser.Email == "" {
			return nil, fmt.Errorf("github verified primary email not found")
		}

		return &ProviderUserInfo{
			ID:    fmt.Sprintf("%d", githubUser.ID),
			Email: githubUser.Email,
			Name:  githubUser.Name,
			Raw:   githubUser,
		}, nil
	case "apple":
		idToken, ok := token.Extra("id_token").(string)
		if !ok {
			return nil, fmt.Errorf("missing id_token from apple")
		}

		claims, err := validateAppleIDToken(idToken, config.ClientID)
		if err != nil {
			return nil, fmt.Errorf("apple id_token validation failed: %v", err)
		}

		if claims.EmailVerified != "true" && claims.EmailVerified != true {
			// Some providers return bool, some return string "true"
			return nil, fmt.Errorf("apple email not verified")
		}

		return &ProviderUserInfo{
			ID:    claims.Subject,
			Email: claims.Email,
			Raw:   claims,
		}, nil
	case "linkedin":
		resp, err := client.Get("https://api.linkedin.com/v2/userinfo")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read Linkedin response body: %v", err)
		}

		log.Debug("OAuth2Login(%s) | Linkedin /userinfo status: %d", provider, resp.StatusCode)
		log.Debug("OAuth2Login(%s) | Linkedin /userinfo raw body: %s", provider, string(bodyBytes))

		var liUser struct {
			Sub           string `json:"sub"`
			Name          string `json:"name"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Picture       string `json:"picture"`
		}

		if err := json.Unmarshal(bodyBytes, &liUser); err != nil {
			return nil, fmt.Errorf("failed to unmarshal linkedin body: %v", err)
		}

		if liUser.Email == "" {
			return nil, fmt.Errorf("linkedin email not found in userinfo")
		}

		return &ProviderUserInfo{
			ID:    liUser.Sub,
			Email: liUser.Email,
			Name:  liUser.Name,
			Raw:   liUser,
		}, nil
	case "facebook":
		resp, err := client.Get("https://graph.facebook.com/me?fields=id,name,email")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read Facebook response body: %v", err)
		}
		log.Debug("OAuth2Login(%s) | Facebook /users/me status: %d", provider, resp.StatusCode)
		log.Debug("OAuth2Login(%s) | Facebook /users/me raw body: %s", provider, string(bodyBytes))

		var fbUser struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Email string `json:"email"`
		}
		if err := json.Unmarshal(bodyBytes, &fbUser); err != nil {
			return nil, err
		}

		if fbUser.Email == "" {
			return nil, fmt.Errorf("facebook email not found")
		}
		return &ProviderUserInfo{
			ID:    fbUser.ID,
			Email: fbUser.Email,
			Name:  fbUser.Name,
			Raw:   fbUser,
		}, nil
	case "amazon":
		resp, err := client.Get("https://api.amazon.com/user/profile")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read Amazon response body: %v", err)
		}
		log.Debug("OAuth2Login(%s) | Amazon /users/profile status: %d", provider, resp.StatusCode)
		log.Debug("OAuth2Login(%s) | Amazon /users/profile raw body: %s", provider, string(bodyBytes))

		var amazonUser struct {
			UserID string `json:"user_id"`
			Email  string `json:"email"`
			Name   string `json:"name"`
		}

		if err := json.Unmarshal(bodyBytes, &amazonUser); err != nil {
			return nil, err
		}

		if amazonUser.Email == "" {
			return nil, fmt.Errorf("amazon email not found")
		}
		return &ProviderUserInfo{
			ID:    amazonUser.UserID,
			Email: amazonUser.Email,
			Name:  amazonUser.Name,
			Raw:   amazonUser,
		}, nil
	case "salesforce":
		// Salesforce usually provides an 'id' URL in the token response
		idURL, ok := token.Extra("id").(string)
		if !ok {
			// Fallback to standard identity URL if not in extra
			idURL = "https://login.salesforce.com/id/00D.../005..." // This is just a pattern
			return nil, fmt.Errorf("salesforce identity URL missing from token")
		}

		resp, err := client.Get(idURL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read Salesforce response body: %v", err)
		}
		log.Debug("OAuth2Login(%s) | Salesforce Identity status: %d", provider, resp.StatusCode)
		log.Debug("OAuth2Login(%s) | Salesforce Identity raw body: %s", provider, string(bodyBytes))

		var sfUser struct {
			ID            string `json:"user_id"`
			Username      string `json:"username"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			DisplayName   string `json:"display_name"`
		}
		if err := json.Unmarshal(bodyBytes, &sfUser); err != nil {
			return nil, err
		}

		if !sfUser.EmailVerified {
			return nil, fmt.Errorf("salesforce email not verified")
		}

		return &ProviderUserInfo{
			ID:    sfUser.ID,
			Email: sfUser.Email,
			Name:  sfUser.DisplayName,
			Raw:   sfUser,
		}, nil

	case "x":
		resp, err := client.Get("https://api.twitter.com/2/users/me?user.fields=id,name,username,confirmed_email")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read X response body: %v", err)
		}

		log.Debug("OAuth2Login(%s) | X /users/me status: %d", provider, resp.StatusCode)
		log.Debug("OAuth2Login(%s) | X /users/me raw body: %s", provider, string(bodyBytes))

		var xResp struct {
			Data struct {
				ID       string `json:"id"`
				Name     string `json:"name"`
				Username string `json:"username"`
				Email    string `json:"confirmed_email"`
			} `json:"data"`
		}
		if err := json.Unmarshal(bodyBytes, &xResp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal X user info: %v", err)
		}

		return &ProviderUserInfo{
			ID:    xResp.Data.ID,
			Name:  xResp.Data.Name,
			Email: xResp.Data.Email,
			Raw:   xResp,
		}, nil

	case "oidc":
		// resp, err := client.Get(config.Endpoint.AuthURL) // This is wrong, should be userinfo endpoint
		// For OIDC we need the userinfo endpoint from metadata
		userinfoURL := ""
		db := globals.GetDBInstance()
		dbProvider, _ := db.GetAuthProviderBySlug("oidc")
		if dbProvider != nil && dbProvider.Metadata != nil {
			var metadata map[string]interface{}
			if err := json.Unmarshal([]byte(*dbProvider.Metadata), &metadata); err == nil {
				if ui, ok := metadata["userinfo_url"].(string); ok {
					userinfoURL = ui
				}
			}
		}

		if userinfoURL == "" {
			return nil, fmt.Errorf("missing userinfo_url for oidc")
		}

		resp, err := client.Get(userinfoURL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read OIDC response body: %v", err)
		}
		log.Debug("OAuth2Login(%s) | OIDC userinfo status: %d", provider, resp.StatusCode)
		log.Debug("OAuth2Login(%s) | OIDC userinfo raw body: %s", provider, string(bodyBytes))

		var oidcUser struct {
			Sub   string `json:"sub"`
			Email string `json:"email"`
			Name  string `json:"name"`
		}
		if err := json.Unmarshal(bodyBytes, &oidcUser); err != nil {
			return nil, err
		}

		return &ProviderUserInfo{
			ID:    oidcUser.Sub,
			Email: oidcUser.Email,
			Name:  oidcUser.Name,
			Raw:   oidcUser,
		}, nil

	default:
		return nil, fmt.Errorf("user info fetch not implemented for %s", provider)
	}
}

type AppleClaims struct {
	jwt.RegisteredClaims
	Email         string      `json:"email"`
	EmailVerified interface{} `json:"email_verified"` // Can be bool or string
}

func validateAppleIDToken(idToken, clientID string) (*AppleClaims, error) {
	resp, err := http.Get("https://appleid.apple.com/auth/keys")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	token, err := jwt.ParseWithClaims(idToken, &AppleClaims{}, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in header")
		}

		for _, key := range jwks.Keys {
			if key.Kid == kid {
				nBytes, _ := base64.RawURLEncoding.DecodeString(key.N)
				eBytes, _ := base64.RawURLEncoding.DecodeString(key.E)
				if len(eBytes) < 4 {
					padded := make([]byte, 4)
					copy(padded[4-len(eBytes):], eBytes)
					eBytes = padded
				}
				eInt := big.NewInt(0).SetBytes(eBytes).Int64()
				return &rsa.PublicKey{
					N: big.NewInt(0).SetBytes(nBytes),
					E: int(eInt),
				}, nil
			}
		}
		return nil, fmt.Errorf("key not found")
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*AppleClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	if claims.Issuer != "https://appleid.apple.com" {
		return nil, fmt.Errorf("invalid issuer")
	}

	foundAud := false
	for _, aud := range claims.Audience {
		if aud == clientID {
			foundAud = true
			break
		}
	}
	if !foundAud {
		return nil, fmt.Errorf("invalid audience")
	}

	return claims, nil
}
