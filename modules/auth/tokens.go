package auth

import (
	"Back/globals"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

// Just for dev
var (
	jwtKey = []byte("x5qFH80ULkKFOBiZnYhW/v2u8sWI5F3ro1wOEE5gm0I=")
)

type Claims struct {
	Username string
	jwt.RegisteredClaims
}

func CreateToken(username string) (string, string, error) {
	config := globals.GetConfig()
	log := globals.GetAppLogger()
	db := globals.GetDBInstance()
	tokenExpirationTime := config.Server.TokenExpirationTime
	tokenExpirationRefreshTime := config.Server.TokenExpirationRefreshTime
	expirationTime := time.Now().Add(time.Duration(tokenExpirationTime) * time.Minute)

	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		log.Error("CreateToken() | Unable to sign token. %v", err.Error())
		return "", "", errors.New("unable to sign token")
	}

	date := jwt.NewNumericDate(time.Now().Add(time.Duration(tokenExpirationRefreshTime) * time.Minute))
	refreshClaims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: date,
		},
	}

	err = db.RevokeRefreshToken(username)
	if err != nil {
		log.Critical("CreateToken() | Unable to revoke refresh token. %s", err.Error())
		return "", "", errors.New("unable to revoke old refresh token")
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(jwtKey)
	err = db.StoreRefreshToken(refreshTokenString, username, date.Time)

	if err != nil {
		log.Error("CreateToken() | Unable to sign refresh token. %s", err.Error())
		return "", "", errors.New("unable to sign refresh token")
	}

	return tokenString, refreshTokenString, nil
}

func ValidateRefreshToken(refreshToken string) (*Claims, error) {
	log := globals.GetAppLogger()
	token, err := jwt.ParseWithClaims(refreshToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
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

func IssueNewTokens(refreshToken string, claims jwt.MapClaims) (string, string, error) {

	db := globals.GetDBInstance()
	username, ok := claims["username"].(string)
	if !ok {
		return "", "", errors.New("no username in the claims")
	}

	oldRefreshToken, err := db.GetRefreshToken(refreshToken)
	if err != nil {
		return "", "", fmt.Errorf("unable to get old refresh token: %w", err)
	}

	if oldRefreshToken.Status == false {
		return "", "", errors.New("token has already been used")
	}

	accessToken, refreshToken, err := CreateToken(username)
	if err != nil {
		return "", "", fmt.Errorf("unable to issue new tokens: %w", err)
	}

	err = db.RevokeRefreshToken(oldRefreshToken.ID)
	if err != nil {
		return "", "", fmt.Errorf("unable to mark old refresh token as used: %w", err)
	}

	return accessToken, refreshToken, nil
}
