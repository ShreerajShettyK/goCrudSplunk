package routes

import (
	"goCrudSplunk/controllers"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

func UserRoutes(router chi.Router, logger *zap.Logger) {
	router.Route("/users", func(r chi.Router) {
		r.Post("/signup", controllers.Signup(logger))
		r.Post("/login", controllers.Login(logger))
		r.Get("/", controllers.GetUsers(logger))
		r.Get("/{userID}", controllers.GetUser(logger))
	})
}
