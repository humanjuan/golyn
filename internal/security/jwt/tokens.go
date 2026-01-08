package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/humanjuan/golyn/globals"
)

type Claims struct {
	SiteID string `json:"site_id"`
	jwt.RegisteredClaims
}

func CreateToken(subject string, siteID string) (string, string, error) {
	return CreateTokenWithRevocation(subject, siteID, true)
}

func CreateTokenWithRevocation(subject string, siteID string, revokeOthers bool) (string, string, error) {
	config := globals.GetConfig()
	log := globals.GetAppLogger()
	db := globals.GetDBInstance()
	jwtKey := []byte(config.Server.JWTSecret)
	tokenExpirationTime := config.Server.TokenExpirationTime
	tokenExpirationRefreshTime := config.Server.TokenExpirationRefreshTime
	expirationTime := time.Now().Add(time.Duration(tokenExpirationTime) * time.Minute)
	issuedAt := time.Now()

	// Get User UUID from database (subject is username)
	var users []struct {
		ID string `db:"id"`
	}
	err := db.Select("SELECT id FROM auth.users WHERE username = $1", &users, subject)
	if err != nil || len(users) == 0 {
		log.Error("CreateToken() | User not found: %s", subject)
		return "", "", errors.New("user not found")
	}
	userUUID := users[0].ID

	claims := &Claims{
		SiteID: siteID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    "Golyn",
			Audience:  jwt.ClaimStrings{"GolynPlatform"},
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		log.Error("CreateToken() | Unable to sign token. %v", err.Error())
		return "", "", errors.New("unable to sign token")
	}

	refreshExpirationTime := time.Now().Add(time.Duration(tokenExpirationRefreshTime) * time.Minute)
	refreshClaims := &Claims{
		SiteID: siteID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    "Golyn",
			Audience:  jwt.ClaimStrings{"GolynPlatform"},
			ExpiresAt: jwt.NewNumericDate(refreshExpirationTime),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
		},
	}

	if revokeOthers {
		err = db.RevokeAllUserRefreshTokens(userUUID)
		if err != nil {
			log.Critical("CreateToken() | Unable to revoke refresh token. %s", err.Error())
			return "", "", errors.New("unable to revoke old refresh token")
		}
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(jwtKey)
	if err != nil {
		log.Error("CreateToken() | Unable to sign refresh token. %s", err.Error())
		return "", "", errors.New("unable to sign refresh token")
	}

	err = db.StoreRefreshToken(refreshTokenString, userUUID, refreshExpirationTime)
	if err != nil {
		log.Error("CreateToken() | Unable to store refresh token. %s", err.Error())
		return "", "", errors.New("unable to store refresh token")
	}

	return tokenString, refreshTokenString, nil
}

func ValidateRefreshToken(refreshToken string) (*Claims, error) {
	log := globals.GetAppLogger()
	config := globals.GetConfig()
	jwtKey := []byte(config.Server.JWTSecret)
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Error("ValidateRefreshToken() | Unexpected signing method. %v", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})

	if err != nil {
		log.Error("ValidateRefreshToken() | %v", err.Error())
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	} else {
		log.Error("ValidateRefreshToken() | Invalid token")
		return nil, errors.New("invalid token")
	}
}

func IssueNewTokens(refreshToken string, claims *Claims) (string, string, error) {
	db := globals.GetDBInstance()
	subject := claims.Subject
	if subject == "" {
		return "", "", errors.New("no sub in the claims")
	}
	siteID := claims.SiteID
	if siteID == "" {
		return "", "", errors.New("no site_id in the claims")
	}

	oldRefreshToken, err := db.GetRefreshToken(refreshToken)
	if err != nil {
		return "", "", fmt.Errorf("unable to get old refresh token: %w", err)
	}

	if oldRefreshToken.Revoked == true {
		return "", "", errors.New("token has already been used")
	}

	accessToken, newRefreshTokenString, err := CreateTokenWithRevocation(subject, siteID, false)
	if err != nil {
		return "", "", fmt.Errorf("unable to issue new tokens: %w", err)
	}

	err = db.RevokeRefreshTokenByID(oldRefreshToken.ID)
	if err != nil {
		return "", "", fmt.Errorf("unable to mark old refresh token as used: %w", err)
	}

	return accessToken, newRefreshTokenString, nil
}

func GetJWTKey() []byte {
	config := globals.GetConfig()
	return []byte(config.Server.JWTSecret)
}
