package auth

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

// Type representing the required level (need to be admin, user, service account) to access a resource
type Type uint64

const (
	// AuthTypeUser means that a user account is required to access a resource
	AuthTypeUser Type = 1 << iota

	// AuthTypeAdmin means that an admin account is required to access a resource
	AuthTypeAdmin Type = 2

	// AuthTypeServiceAccount means that a service account is required to access a resource
	AuthTypeServiceAccount Type = 4

	// AuthTypeAll means that any account type can access the ressource (anonymous not allowed)
	AuthTypeAll Type = 8
)

// Handler represents a protected route
type Handler struct {
	Path        string
	Handler     func(http.ResponseWriter, *http.Request)
	Permissions Type
}

// HasFlag is useful to check if the current route got the specific user flag
// We can protect a route like AuthTypeAdmin | AuthTypeServiceAccount, it should then allow only those two types
func (t Type) HasFlag(flag Type) bool {
	return t|flag == t
}

// JWTClaims represents the claims in the JWT
type JWTClaims struct {
	Username string `json:"username"`
	Type     string `json:"type"`
	jwt.StandardClaims
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
	token, err := jwt.Parse(reqToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		//TODO: currently HMAC, could/should be asymmetrical
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if token.Valid {
		// TODO: need to map to JWTClaims struct, use jwt.ParseWithClaims
		claims, _ := token.Claims.(jwt.MapClaims)
		if _, ok := claims["exp"]; !ok {
			http.Error(w, "token missing expiry claim", http.StatusBadRequest)
		} else {
			//TODO: verifying presence of type claim
			userType, _ := claims["type"].(string)
			return ah.checkTokenAuthorization(r, userType)
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
