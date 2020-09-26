package auth

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

// Handler represents a protected route
type Handler struct {
	Path        string
	Handler     func(http.ResponseWriter, *http.Request)
	Permissions Type
}

func (ah Handler) checkTokenAuthorization(r *http.Request, userTypeClaim string) bool {
	userTypeUint, err := strconv.ParseUint(userTypeClaim, 10, 64)
	if err != nil {
		fmt.Printf("error while converting userType from token, %s", err.Error())
		return false
	}

	userType := Type(userTypeUint)
	return ah.Permissions.HasFlag(userType) || ah.Permissions == AuthTypeAll
}

func (ah Handler) extractTokenFromHeaders(w http.ResponseWriter, r *http.Request) string {
	reqToken := r.Header.Get("Authorization")
	splitToken := strings.Split(reqToken, "Bearer ")

	if len(splitToken) != 2 {
		fmt.Printf("bad authorization header format\n")
		http.Error(w, "bad authorization header format\n", http.StatusBadRequest)
		return ""
	}
	return splitToken[1]
}

func (ah Handler) validateToken(w http.ResponseWriter, r *http.Request, reqToken string) bool {
	token, err := jwt.ParseWithClaims(reqToken, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		//TODO: currently HMAC, could/should be asymmetrical
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if token.Valid {
		if claims, ok := token.Claims.(*JWTClaims); !ok {
			http.Error(w, "token missing proper claims", http.StatusBadRequest)
		} else {
			return ah.checkTokenAuthorization(r, claims.Type)
		}
		return true
	}
	//TODO: writing multiple times in w when unauthorized
	http.Error(w, err.Error(), http.StatusInternalServerError)
	return false
}

func (ah Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqToken := ah.extractTokenFromHeaders(w, r)
	if reqToken != "" {
		if authorized := ah.validateToken(w, r, reqToken); authorized {
			ah.Handler(w, r)
		} else {
			http.Error(w, "unauthorized access", http.StatusUnauthorized)
		}
	}
}
