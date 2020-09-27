package auth

import jwt "github.com/dgrijalva/jwt-go"

// JWTClaims represents the claims in the JWT
type JWTClaims struct {
	Username    string              `json:"username"`
	Type        string              `json:"type"`
	Permissions map[string][]string `json:"permissions"`
	jwt.StandardClaims
}
