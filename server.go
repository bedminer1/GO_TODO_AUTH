package main

import (
	"log"

	"github.com/bedminer1/todo/handlers"
	"github.com/bedminer1/todo/models"
	"github.com/bedminer1/todo/todo"
	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var db *gorm.DB

func InitDB() *gorm.DB {
	database, err := gorm.Open(sqlite.Open("tasks.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect to database")
	}

	err = database.AutoMigrate(&models.BlacklistedToken{}, &models.User{}, &models.Task{})
	if err != nil {
		log.Fatalf("failed to migrate database schema")
	}

	return database
}

func main() {
	e := echo.New()

	// Initialize DB and create handler
	db = InitDB()
	
	t := todo.NewTodoService(db)
	h := handlers.NewHandler(t, db)

	e.POST("/login", h.HandleLogin)

	r := e.Group("/auth")
	config := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(handlers.JwtCustomClaims)
		},
		SigningKey: []byte(handlers.SecretKey),
	}
	r.Use(echojwt.WithConfig(config))
	r.Use(handlers.JwtMiddleware)
	r.POST("/logout", h.HandleLogout)
	r.GET("/tasks", h.HandleList)
	r.POST("/tasks", h.HandleAdd)
	r.PUT("/tasks/:id", h.HandleComplete)
	r.DELETE("/tasks/:id", h.HandleDelete)

	e.Logger.Fatal(e.Start(":1234"))
}
