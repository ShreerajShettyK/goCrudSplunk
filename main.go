// package main

// import (
// 	"log"
// 	"net/http"
// 	"os"

// 	"go-chat-app/routes"
// 	"github.com/joho/godotenv"
// )

// func main() {
// 	err := godotenv.Load(".env")
// 	if err != nil {
// 		log.Fatal("Error loading .env file")
// 	}

// 	port := os.Getenv("PORT")
// 	if port == "" {
// 		port = "8000"
// 	}

// 	// Setup routes
// 	routes.AuthRoutes()
// 	routes.UserRoutes()

// 	http.HandleFunc("/api-1", func(w http.ResponseWriter, r *http.Request) {
// 		w.WriteHeader(http.StatusOK)
// 		w.Write([]byte(`{"success":"Access granted for api-1"}`))
// 	})

// 	http.HandleFunc("/api-2", func(w http.ResponseWriter, r *http.Request) {
// 		w.WriteHeader(http.StatusOK)
// 		w.Write([]byte(`{"success":"Access granted for api-2"}`))
// 	})

// 	log.Fatal(http.ListenAndServe(":"+port, nil))

// 	// userPoolID := "us-east-1_bcezkbKcV"
//     // clientID :="3nhdeivacuskqno6992ar4bikg"
//     // clientSecret :="sfhflsbea9vecouaqb9eik4bu6410qijr29uklcphv9mv5k0qvs"
//     // username := "user"
//     // password := "User@123"

//     // token, err := cognito.GetJWTToken(userPoolID, clientID, clientSecret, username, password)
//     // if err != nil {
//     //     fmt.Println("Error:", err)
//     //     return
//     // }

//     // fmt.Println("JWT Token:", token)
// }

// main.go
package main

import (
	"encoding/json"
	"go-chat-app/cognito"
	"go-chat-app/routes"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	// Setup routes
	routes.AuthRoutes()
	routes.UserRoutes()

	http.HandleFunc("/api-1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success":"Access granted for api-1"}`))
	})

	http.HandleFunc("/api-2", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success":"Access granted for api-2"}`))
	})

	// New route to get JWT token
	http.HandleFunc("/get-jwt-token", func(w http.ResponseWriter, r *http.Request) {
		userPoolID := os.Getenv("USER_POOL_ID")
		clientID := os.Getenv("CLIENT_ID")
		clientSecret := os.Getenv("CLIENT_SECRET")
		username := os.Getenv("username") // Replace with actual username
		password := os.Getenv("password") // Replace with actual password

		token, err := cognito.GetJWTToken(userPoolID, clientID, clientSecret, username, password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"jwt_token": token})
	})

	log.Fatal(http.ListenAndServe(":"+port, nil))
}
