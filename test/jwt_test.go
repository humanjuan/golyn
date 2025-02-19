/*
It requires setting the following configuration on the server:

[server]
tokenExpirationTime = 1
tokenExpirationRefreshTime = 3

*/

package test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"
)

type LoginCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

const server string = "https://golyn.local/api/v1"

func TestAuthenticationFlow(t *testing.T) {
	client := createHttpClient()

	t.Run("Login and Obtain Tokens", func(t *testing.T) {
		loginResponse, err := login(client, t)
		if err != nil {
			t.Fatalf("[NOK] Failed to login: %s", err.Error())
		}

		// Validar que el access token funcione
		if !getCountries(client, loginResponse.AccessToken, t) {
			t.Fatal("[NOK] Failed to retrieve countries using valid access token")
		}
		t.Log("[OK] Successfully tested access token retrieval.")
	})

	t.Run("Expired Access Token Simulation", func(t *testing.T) {
		// Realizar el login para obtener el token inicial
		loginResponse, err := login(client, t)
		if err != nil {
			t.Fatalf("[NOK] Failed to login: %s", err.Error())
		}

		// Validar que el access token funcione
		if !getCountries(client, loginResponse.AccessToken, t) {
			t.Fatal("[NOK] Failed to retrieve countries using valid access token")
		}
		t.Log("[OK] Successfully tested access token retrieval.")

		// Simular un tiempo de expiración del access token
		t.Log("[INFO] Simulating access token expiration (waiting 60 seconds)...")
		time.Sleep(60 * time.Second)

		// Intentar acceder a recursos con un token que debería estar expirado
		if getCountries(client, loginResponse.AccessToken, t) {
			t.Fatal("[NOK] Unexpectedly, the expired access token succeeded.")
		}
		t.Log("[OK] Access token expired and failed as expected.")
	})

	t.Run("Refresh Token and Obtain New Access Token", func(t *testing.T) {
		loginResponse, err := login(client, t)
		if err != nil {
			t.Fatalf("[NOK] Failed to login: %s", err.Error())
		}

		// Validar que el access token funcione
		if !getCountries(client, loginResponse.AccessToken, t) {
			t.Fatal("[NOK] Failed to retrieve countries using valid access token")
		}
		t.Log("[OK] Successfully tested access token retrieval.")

		newAccessToken, err := refreshAccessToken(client, loginResponse.RefreshToken, t)
		if err != nil {
			t.Fatalf("[NOK] Failed to refresh access token: %s", err.Error())
		}

		// Intentar acceder a recursos con un nuevo token
		if !getCountries(client, newAccessToken, t) {
			t.Fatal("[NOK] Failed to retrieve countries using valid access token")
		}
		t.Log("[OK] Successfully tested access token retrieval.")
	})

	t.Run("Expired Refreshed Token", func(t *testing.T) {
		loginResponse, err := login(client, t)
		if err != nil {
			t.Fatalf("[NOK] Failed to login: %s", err.Error())
		}

		// Refrescar el token de acceso
		newAccessToken, err := refreshAccessToken(client, loginResponse.RefreshToken, t)
		if err != nil {
			t.Fatalf("[NOK] Failed to refresh access token: %s", err.Error())
		}

		// Simular la expiración del token refrescado
		t.Log("[INFO] Simulating refresh token expiration...")
		time.Sleep(60 * time.Second)

		// Intentar usar el token renovado después de su expiración
		if getCountries(client, newAccessToken, t) {
			t.Fatal("[NOK] Refreshed token should be expired")
		} else {
			t.Logf("[OK] Refreshed token expired as expected")
		}
	})
}

func createHttpClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
	}

	return &http.Client{
		Transport: tr,
		Jar:       jar,
	}

}

/*
func login(client *http.Client, t *testing.T) (*LoginResponse, error) {
	loginData := &LoginCredentials{
		Username: "juan@gmail.com",
		Password: "Pass.2023",
	}

	loginDataJson, _ := json.Marshal(loginData)
	resp, err := client.Post(server+"/login", "application/json", bytes.NewBuffer(loginDataJson))
	if err != nil {
		return nil, fmt.Errorf("failed to make login HTTP request: %s", err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code for login: %v", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read login response body: %s", err.Error())
	}

	loginResponse := &LoginResponse{}
	err = json.Unmarshal(data, loginResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse login response JSON: %s", err.Error())
	}

	t.Logf("[OK] Login successful. AccessToken: %s", loginResponse.AccessToken)
	return loginResponse, nil
}
*/

func login(client *http.Client, t *testing.T) (*LoginResponse, error) {
	loginData := &LoginCredentials{
		Username: "juan@gmail.com",
		Password: "Pass.2023",
	}

	loginDataJson, _ := json.Marshal(loginData)
	resp, err := client.Post(server+"/login", "application/json", bytes.NewBuffer(loginDataJson))
	if err != nil {
		return nil, fmt.Errorf("failed to make login HTTP request: %s", err.Error())
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			t.Logf("[WARN] Failed to close login response body: %s", err.Error())
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code for login: %v", resp.StatusCode)
	}

	// Leer el cuerpo de la respuesta para obtener el AccessToken
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read login response body: %s", err.Error())
	}

	loginResponse := &LoginResponse{}
	err = json.Unmarshal(data, loginResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse login response JSON: %s", err.Error())
	}

	cookies := resp.Header["Set-Cookie"]
	if len(cookies) == 0 {
		return nil, http.ErrNoCookie
	}

	for _, c := range cookies {
		if strings.HasPrefix(c, "refreshToken=") {
			loginResponse.RefreshToken = strings.Split(strings.Split(c, "refreshToken=")[1], ";")[0]
			break
		}
	}

	if loginResponse.RefreshToken == "" {
		return nil, fmt.Errorf("failed to extract refresh token from Set-Cookie header")
	}

	t.Logf("[OK] Login successful. AccessToken: %s, RefreshToken: %s", loginResponse.AccessToken, loginResponse.RefreshToken)
	return loginResponse, nil
}

func refreshAccessToken(client *http.Client, refreshToken string, t *testing.T) (string, error) {
	req, _ := http.NewRequest("POST", server+"/refresh_token", nil)

	// Añadir el refreshToken como una cookie
	req.AddCookie(&http.Cookie{
		Name:  "refreshToken",
		Value: refreshToken,
		Path:  "/",
	})

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make refresh request: %s", err.Error())
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			t.Logf("[WARN] Failed to close refresh response body: %s", err.Error())
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code during refresh: %v", resp.StatusCode)
	}

	// Leer la respuesta para obtener el nuevo access token
	data, _ := io.ReadAll(resp.Body)
	var refreshResponse LoginResponse
	err = json.Unmarshal(data, &refreshResponse)
	if err != nil {
		return "", err
	}

	t.Logf("[OK] Token refreshed successfully. New AccessToken: %s", refreshResponse.AccessToken)
	return refreshResponse.AccessToken, nil
}

func getCountries(client *http.Client, token string, t *testing.T) bool {
	req, _ := http.NewRequest("GET", server+"/get_countries", nil)
	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("[NOK] HTTP request failed: %s", err.Error())
		return false
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			t.Errorf("error closing response body: %v", err)
		}
	}(resp.Body)

	if resp.StatusCode == http.StatusOK {
		return true
	}
	return false
}
