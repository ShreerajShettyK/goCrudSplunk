package routes

import (
	"goCrudSplunk/controllers"

	"github.com/go-chi/chi"
	"go.uber.org/zap"
)

// AuthRoutes now expects *chi.Mux instead of *http.ServeMux
func AuthRoutes(router *chi.Mux, logger *zap.Logger) {
	router.HandleFunc("/users/signup", controllers.Signup(logger))
	router.HandleFunc("/users/login", controllers.Login(logger))
}
