package auth

import (
	platjwt "github.com/humanjuan/golyn/internal/security/jwt"
)

type Claims = platjwt.Claims

func CreateToken(subject string, siteID string, ip, ua string) (string, string, error) {
	return platjwt.CreateToken(subject, siteID, ip, ua)
}

func ValidateRefreshToken(refreshToken string) (*platjwt.Claims, error) {
	return platjwt.ValidateRefreshToken(refreshToken)
}

func IssueNewTokens(refreshToken string, claims *platjwt.Claims, ip, ua string) (string, string, error) {
	return platjwt.IssueNewTokens(refreshToken, claims, ip, ua)
}
