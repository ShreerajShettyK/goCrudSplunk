package routes

import (
	"goCrudSplunk/controllers"

	"github.com/go-chi/chi"
	"go.uber.org/zap"
)

// AuthRoutes now expects *chi.Mux instead of *http.ServeMux
func UserRoutes(router *chi.Mux, logger *zap.Logger) {
	router.Get("/users", controllers.GetUsers(logger))
	router.Get("/users/{userID}", controllers.GetUser(logger))
}
