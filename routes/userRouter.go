package routes

import (
	"goCrudSplunk/controllers"
	"net/http"
)

func UserRoutes() {
	// Only protect the routes that should require authentication
	// http.Handle("/users", middleware.Authenticate(http.HandlerFunc(controllers.GetUsers)))
	// http.Handle("/users/", middleware.Authenticate(http.HandlerFunc(controllers.GetUser)))
	http.Handle("/users", http.HandlerFunc(controllers.GetUsers))
	http.Handle("/users/", http.HandlerFunc(controllers.GetUser))
}
