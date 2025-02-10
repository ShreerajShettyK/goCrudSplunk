package routes

import (
	"goCrudSplunk/controllers"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.uber.org/zap"
)

func UserRoutes(router chi.Router, logger *zap.Logger) {
	router.Use(otelhttp.NewMiddleware("service")) // Add tracing middleware

	router.Route("/users", func(r chi.Router) {
		r.Post("/signup", controllers.Signup(logger))
		r.Post("/login", controllers.Login(logger))
		r.Get("/", controllers.GetUsers(logger))
		r.Get("/{userID}", controllers.GetUser(logger))
		r.Get("/getCourse", controllers.GetCourse(logger))
	})
}
