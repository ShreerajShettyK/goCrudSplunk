package routes

import (
	"net/http"
	"go-chat-app/controllers"
)

func AuthRoutes() {
	http.HandleFunc("/users/signup", controllers.Signup)
	http.HandleFunc("/users/login", controllers.Login)
}
