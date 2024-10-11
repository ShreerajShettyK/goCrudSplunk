package routes

import (
	"goCrudSplunk/controllers"
	"net/http"
)

func UserRoutes() {
	// Only protect the routes that should require authentication
	// http.Handle("/users", middleware.Authenticate(http.HandlerFunc(controllers.GetUsers)))
	// http.Handle("/users/", middleware.Authenticate(http.HandlerFunc(controllers.GetUser)))
	http.HandleFunc("/users", controllers.GetUsers)
	http.HandleFunc("/users/", controllers.GetUser)
}
