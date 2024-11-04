package main

import (
	"github.com/bedminer1/todo/handlers"
	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()

	e.POST("/tasks", handlers.AddTodo)

	e.Logger.Fatal(e.Start(":1234"))
}