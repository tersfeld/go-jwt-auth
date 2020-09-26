package auth

import (
	"os"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
)

func TestGenerateJWT(t *testing.T) {
	claims := JWTClaims{Username: "test", Type: "4"}
	generatedToken, err := GenerateJWT(claims, 60)
	if err != nil {
		t.Errorf("Error while generating a JWT %s", err.Error())
	}

	token, err := jwt.ParseWithClaims(generatedToken, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		t.Errorf("Error while parsing the JWT %s", err.Error())
	}

	if !token.Valid {
		t.Errorf("Token is not valid")
	}

	if c, ok := token.Claims.(*JWTClaims); !ok {
		t.Errorf("Token doesn't have the proper claims")
	} else {
		if claims.Username != c.Username || claims.Type != c.Type {
			t.Errorf("Tokens don't match")
		}
	}
}
