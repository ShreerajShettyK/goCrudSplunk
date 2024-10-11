package routes

import (
	"goCrudSplunk/controllers"

	"github.com/go-chi/chi"
	"go.uber.org/zap"
)

// AuthRoutes now expects *chi.Mux instead of *http.ServeMux
func AuthRoutes(router *chi.Mux, logger *zap.Logger) {
	router.Post("/users/signup", controllers.Signup(logger))
	router.Post("/users/login", controllers.Login(logger))
}
