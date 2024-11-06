package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/bedminer1/todo/todo"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type JwtCustomClaims struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
	jwt.RegisteredClaims
}

var SecretKey = "f2g(&*kjha12$34%^&*148f6"

// for database injection
type Handler struct {
	db *gorm.DB
}

func NewHandler(db *gorm.DB) *Handler {
	return &Handler{db: db}
}

func (h *Handler) HandleLogin(c echo.Context) error {
	var user todo.User
	username := c.FormValue("username")
	password := c.FormValue("password")

	err := h.db.Where("username = ? AND password = ?", username, password).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return echo.ErrUnauthorized
		}
		return err
	}

	claims := &JwtCustomClaims{
		username,
		true,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)),
			ID:        uuid.NewString(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString([]byte(SecretKey))
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, echo.Map{
		"token": t,
	})
}

func HandleAdd(c echo.Context) error {
	task := c.FormValue("task")
	urgency := c.FormValue("urgency")
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*JwtCustomClaims)
	author := claims.Name

	newTask, err := todo.AddTask(author, task, urgency)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"error": "internal error occurred while adding the task",
		})
	}
	return c.JSON(http.StatusCreated, newTask)
}

func HandleComplete(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*JwtCustomClaims)
	author := claims.Name
	id, _ := strconv.Atoi(c.Param("id"))

	task, err := todo.CompleteTask(id, author)
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

func HandleDelete(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*JwtCustomClaims)
	author := claims.Name
	id, _ := strconv.Atoi(c.Param("id"))

	err := todo.DeleteTask(id, author)
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

func HandleList(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*JwtCustomClaims)
	author := claims.Name

	tasks := todo.ListTasks(author)

	return c.JSON(http.StatusOK, tasks)
}
