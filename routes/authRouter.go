package routes

import (
	"goCrudSplunk/controllers"
	"net/http"
)

func AuthRoutes() {
	http.HandleFunc("/users/signup", controllers.Signup)
	http.HandleFunc("/users/login", controllers.Login)
}
