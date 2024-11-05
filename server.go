package main

import (
	"log"

	"github.com/bedminer1/todo/handlers"
	"github.com/bedminer1/todo/todo"
	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()

	if err := todo.InitDB(); err != nil {
		log.Fatalf("Could not init db: %v", err)
	}

	e.POST("/login", handlers.HandleLogin)

	r := e.Group("/auth")
	config := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(handlers.JwtCustomClaims)
		},
		SigningKey: []byte(handlers.SecretKey),
	}
	r.Use(echojwt.WithConfig(config))
	r.GET("/tasks", handlers.HandleList)
	r.POST("/tasks", handlers.HandleAdd)
	r.PUT("/tasks/:id", handlers.HandleComplete)
	r.DELETE("/tasks/:id", handlers.HandleDelete)

	e.Logger.Fatal(e.Start(":1234"))
}
