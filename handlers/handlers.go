package handlers

import (
	"net/http"
	"time"

	"github.com/bedminer1/todo/todo"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

type JwtCustomClaims struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
	jwt.RegisteredClaims
}

var SecretKey = "f2g(&*kjha12$34%^&*148f6"

func HandleLogin(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	if username != "bed" || password != "bedspassword" {
		return echo.ErrUnauthorized
	}

	claims := &JwtCustomClaims{
		username,
		true,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)),
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

	newTask, err := todo.AddUser(author, task, urgency)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, newTask)
}

func HandleComplete(c echo.Context) error {
	task := todo.Task{}
	return c.JSON(http.StatusOK, task)
}

func HandleDelete(c echo.Context) error {
	return c.NoContent(http.StatusNoContent)
}

func HandleList(c echo.Context) error {
	// make sure only viewable if author name matches jwt
	return nil
}