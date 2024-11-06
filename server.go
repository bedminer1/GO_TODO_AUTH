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
	"gorm.io/gorm/logger"
)

var db *gorm.DB

func InitDB() *gorm.DB {
	database, err := gorm.Open(sqlite.Open("tasks.db"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Fatalf("failed to connect to database")
	}

	err = database.AutoMigrate(&models.BlacklistedToken{}, &models.User{}, &models.Task{})
	if err != nil {
		log.Fatalf("failed to migrate database schema: %v", err)
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
	e.POST("/signup", h.HandleSignup)

	r := e.Group("/auth")
	config := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(handlers.JwtCustomClaims)
		},
		SigningKey: []byte(handlers.SecretKey),
	}
	r.Use(echojwt.WithConfig(config))
	r.Use(h.JwtMiddleware)
	r.POST("/logout", h.HandleLogout)
	r.GET("/tasks", h.HandleList)
	r.POST("/tasks", h.HandleAdd)
	r.PUT("/tasks/:id", h.HandleComplete)
	r.DELETE("/tasks/:id", h.HandleDelete)
	r.POST("/tasks/:task_id", h.HandleGiveReadPermissions)

	e.Logger.Fatal(e.Start(":1234"))
}

// task4 id: ae2bd259-5e7b-4de6-9504-384532d49bdc
// test_user_5 id: e16f8c6c-1524-4f8e-8bbd-55d197d4e0db
// test_user_4 jwt: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGVzdF91c2VyXzQiLCJhZG1pbiI6dHJ1ZSwiZXhwIjoxNzMxMTcyMjU0LCJqdGkiOiI5NTkyOWUwNy1lNjE0LTQzMmUtYjY0Zi1kZTFiMDZiZDI3MzQifQ.2RYtjA8J2XxN5W370bKPUldgeeXJqrb5E9rALX4k0C8