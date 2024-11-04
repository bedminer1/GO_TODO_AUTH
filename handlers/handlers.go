package handlers

import (
	"net/http"

	"github.com/bedminer1/todo/todo"
	"github.com/labstack/echo/v4"
)

func AddTodo(c echo.Context) error {
	task := c.FormValue("task")
	urgency := c.FormValue("urgency")

	newTask, err := todo.AddUser(task, urgency)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, newTask)
}