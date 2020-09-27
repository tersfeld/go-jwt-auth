package auth

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

// Handler represents a protected route
type Handler struct {
	Path                string
	Handler             func(http.ResponseWriter, *http.Request)
	Permissions         Type
	RequestedResourceID string
}

func (ah Handler) checkUserTypeAuthorization(r *http.Request, userTypeClaim string) bool {
	userTypeUint, err := strconv.ParseUint(userTypeClaim, 10, 64)
	if err != nil {
		fmt.Printf("error while converting userType from token, %s", err.Error())
		return false
	}

	userType := Type(userTypeUint)
	return ah.Permissions.HasFlag(userType) || ah.Permissions == AuthTypeAll
}

func (ah Handler) checkResourceAccessAuthorization(r *http.Request, requestedResourceType string, permissions map[string][]string) bool {
	vars := mux.Vars(r)
	resourceTypeValue := vars[requestedResourceType]

	// no need to check for resource access as none have been specified
	if requestedResourceType == "" {
		return true
	}

	userAuthorizedResourceValues := permissions[requestedResourceType]

	for _, userAuthorizedResourceValue := range userAuthorizedResourceValues {
		if userAuthorizedResourceValue == resourceTypeValue {
			return true
		}
	}

	return false
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

func (ah Handler) validateToken(w http.ResponseWriter, r *http.Request, reqToken string) (bool, *JWTClaims) {
	token, err := jwt.ParseWithClaims(reqToken, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		//TODO: currently HMAC, could/should be asymmetrical
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if token != nil && token.Valid {
		claims, ok := token.Claims.(*JWTClaims)
		if !ok {
			http.Error(w, "token missing proper claims", http.StatusBadRequest)
		}
		return true, claims
	} else {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false, nil
	}
}

func (ah Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqToken := ah.extractTokenFromHeaders(w, r)
	if reqToken != "" {
		valid, claims := ah.validateToken(w, r, reqToken)
		if valid {
			if ah.checkUserTypeAuthorization(r, claims.Type) && ah.checkResourceAccessAuthorization(r, ah.RequestedResourceID, claims.Permissions) {
				ah.Handler(w, r)
			} else {
				http.Error(w, "unauthorized access", http.StatusUnauthorized)
			}
		} else {
			http.Error(w, "unauthorized access", http.StatusUnauthorized)
		}
	}
}
