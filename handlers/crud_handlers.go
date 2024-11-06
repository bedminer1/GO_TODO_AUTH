package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/bedminer1/todo/todo"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type JwtCustomClaims struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
	jwt.RegisteredClaims
}

const SecretKey = "f2g(&*kjha12$34%^&*148f6"

// for database injection
type Handler struct {
	DB *gorm.DB
	T  *todo.TodoService
}

func NewHandler(t *todo.TodoService, db *gorm.DB) *Handler {
	return &Handler{T: t, DB: db}
}

// func (h *Handler) HandleChangeName(c echo.Context) error {

// }

func (h *Handler) HandleAdd(c echo.Context) error {
	task := c.FormValue("task")
	urgency := c.FormValue("urgency")
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*JwtCustomClaims)
	author := claims.Name

	newTask, err := h.T.AddTask(author, task, urgency)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "internal error occurred while adding the task",
		})
	}
	return c.JSON(http.StatusCreated, newTask)
}

func (h *Handler) HandleComplete(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*JwtCustomClaims)
	author := claims.Name
	id, _ := strconv.Atoi(c.Param("id"))

	task, err := h.T.CompleteTask(id, author)
	if err != nil {
		switch {
		case errors.Is(err, todo.ErrTaskNotFound):
			return c.JSON(http.StatusNotFound, echo.Map{"error": err.Error()})
		case errors.Is(err, todo.ErrPermissionDenied):
			return c.JSON(http.StatusForbidden, echo.Map{"error": err.Error()})
		default:
			return c.JSON(http.StatusInternalServerError, echo.Map{"error": "unexpected error occurred"})
		}
	}
	return c.JSON(http.StatusOK, task)
}

func (h *Handler) HandleDelete(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*JwtCustomClaims)
	author := claims.Name
	id, _ := strconv.Atoi(c.Param("id"))

	err := h.T.DeleteTask(id, author)
	if err != nil {
		switch {
		case errors.Is(err, todo.ErrTaskNotFound):
			return c.JSON(http.StatusNotFound, echo.Map{"error": err.Error()})
		case errors.Is(err, todo.ErrPermissionDenied):
			return c.JSON(http.StatusForbidden, echo.Map{"error": err.Error()})
		default:
			return c.JSON(http.StatusInternalServerError, echo.Map{"error": "unexpected error occurred"})
		}
	}

	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) HandleList(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*JwtCustomClaims)
	author := claims.Name

	tasks := h.T.ListTasks(author)

	return c.JSON(http.StatusOK, tasks)
}
