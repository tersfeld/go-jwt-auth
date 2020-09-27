package auth

import (
	"os"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
)

func validateTestToken(t *testing.T, tokenStr string) JWTClaims {
	token, err := jwt.ParseWithClaims(tokenStr, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		t.Errorf("Error while parsing the JWT %s", err.Error())
	}

	if !token.Valid {
		t.Errorf("Token is not valid")
	}

	c, ok := token.Claims.(*JWTClaims)
	if !ok {
		t.Errorf("Token doesn't have the proper claims")
	}
	return *c
}

func generateTestToken(t *testing.T) (string, JWTClaims) {
	claims := JWTClaims{Username: "test", Type: "1", Permissions: map[string][]string{"teamId": {"12345"}}}
	generatedToken, err := GenerateJWT(claims, 60)
	if err != nil {
		t.Errorf("Error while generating a JWT %s", err.Error())
	}

	c := validateTestToken(t, generatedToken)
	if claims.Username != c.Username || claims.Type != c.Type {
		t.Errorf("Tokens don't match")
	}
	return generatedToken, c
}

func TestGenerateJWT(t *testing.T) {
	generateTestToken(t)
}

func TestRefreshJWT(t *testing.T) {
	generatedToken, generatedTokenClaims := generateTestToken(t)

	refreshedToken, err := RefreshJWT(generatedToken, 30)
	if err != nil {
		t.Errorf("Error while refreshing a JWT %s", err.Error())
	}

	refreshedTokenClaims := validateTestToken(t, refreshedToken)
	if refreshedTokenClaims.Username != generatedTokenClaims.Username || refreshedTokenClaims.Type != generatedTokenClaims.Type {
		t.Errorf("Tokens don't match")
	}
}
