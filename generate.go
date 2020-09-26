package auth

import (
	"fmt"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

// GenerateJWT used to generate a JWT based on the given claims and expiry in minutes
func GenerateJWT(claims JWTClaims, expiryInMinutes int) (string, error) {
	claims.StandardClaims.ExpiresAt = time.Now().Add(time.Duration(expiryInMinutes) * time.Minute).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}
	return ss, nil
}

// RefreshJWT used to refresh a valid JWT expiry in minutes
func RefreshJWT(tokenToRefreshStr string, expiryInMinutes int) (string, error) {
	claims := &JWTClaims{}
	tokenToRefresh, err := jwt.ParseWithClaims(tokenToRefreshStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return "", err
	}
	if !tokenToRefresh.Valid {
		return "", fmt.Errorf("token to refresh is not valid")
	}

	claims.StandardClaims.ExpiresAt = time.Now().Add(time.Duration(expiryInMinutes) * time.Minute).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", fmt.Errorf("error while signing the refreshed token")
	}
	return ss, nil
}
