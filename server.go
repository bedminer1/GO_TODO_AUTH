package main

import (
	"github.com/bedminer1/todo/handlers"
	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()

	e.POST("/login", handlers.HandleLogin)

	r := e.Group("/auth")
	config := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(handlers.JwtCustomClaims)
		},
		SigningKey: []byte(handlers.SecretKey),
	}
	r.Use(echojwt.WithConfig(config))
	r.POST("/tasks", handlers.HandleAdd)

	e.Logger.Fatal(e.Start(":1234"))
}
