package middleware
 
import (
    "context"
    "fmt"
    "net/http"
    "os"
    "strings"
 
    "github.com/ShreerajShettyK/cognitoJwtAuthenticator"
)
 
func Authenticate(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Extract the JWT token from the Authorization header
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
            return
        }
 
        // Split the header value to extract the token part
        authToken := strings.Split(authHeader, "Bearer ")
        if len(authToken) != 2 {
            http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
            return
        }
        uiClientToken := authToken[1]
 
        // Validate the JWT token
        ctx := context.Background()
        region := os.Getenv("REGION")
        userPoolID := os.Getenv("USER_POOL_ID")
        tokenString := uiClientToken
 
        _, err := cognitoJwtAuthenticator.ValidateToken(ctx, region, userPoolID, tokenString)
        if err != nil {
            http.Error(w, fmt.Sprintf("Token validation error: %s", err), http.StatusUnauthorized)
            return
        }
 
        // Token is valid, proceed with the request
        next.ServeHTTP(w, r)
    })
}