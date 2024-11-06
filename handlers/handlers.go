package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/bedminer1/todo/models"
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

const SecretKey = "f2g(&*kjha12$34%^&*148f6"

var (
	blacklist      = make(map[string]time.Time)
	blacklistMutex sync.RWMutex
)

func AddTokenToBlacklist(tokenID string, expiration time.Time) {
	blacklistMutex.Lock()
	defer blacklistMutex.Unlock()
	blacklist[tokenID] = expiration
}

func IsTokenBlacklisted(tokenID string) bool {
	blacklistMutex.RLock()
	defer blacklistMutex.RUnlock()
	expiration, found := blacklist[tokenID]
	if !found {
		return false
	}

	// remove expired tokens
	if time.Now().After(expiration) {
		blacklistMutex.Lock()
		delete(blacklist, tokenID)
		blacklistMutex.Unlock()
		return false
	}
	return true
}

// for database injection
type Handler struct {
	DB *gorm.DB
	T  *todo.TodoService
}

func NewHandler(t *todo.TodoService, db *gorm.DB) *Handler {
	return &Handler{T: t, DB: db}
}

func (h *Handler) HandleLogin(c echo.Context) error {
	var user models.User
	username := c.FormValue("username")
	password := c.FormValue("password")

	err := h.DB.Where("username = ? AND password = ?", username, password).First(&user).Error
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

func addTokenToBlackList(tokenID, user string, expiration time.Time, db *gorm.DB) error {
	token := models.BlacklistedToken{
		ID:         tokenID,
		User:       user,
		Expiration: expiration,
	}
	cleanupExpiredTokens(db)
	return db.Create(&token).Error
}

func isTokenBlacklisted(tokenID string, db *gorm.DB) (bool, error) {
	var token models.BlacklistedToken
	err := db.Where("id = ? AND expiration > ?", tokenID, time.Now()).First(&token).Error
	if err == gorm.ErrRecordNotFound {
		return false, nil
	}

	return err == nil, err
}

func cleanupExpiredTokens(db *gorm.DB) error {
	return db.Where("expiration < ?", time.Now()).Delete(&models.BlacklistedToken{}).Error
}

func (h *Handler) HandleLogout(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*JwtCustomClaims)

	err := addTokenToBlackList(claims.ID, claims.Name, claims.ExpiresAt.Time, h.DB)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to blacklist token")
	}

	return c.JSON(http.StatusOK, echo.Map{
		"message": "Successfully logged out",
	})
}

func (h *Handler) JwtMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		user := c.Get("user").(*jwt.Token)
		claims := user.Claims.(*JwtCustomClaims)

		isBlacklisted, err := isTokenBlacklisted(claims.ID, h.DB)
		if err != nil {
			return echo.ErrInternalServerError
		}
		if isBlacklisted {
			return echo.ErrUnauthorized
		}

		return next(c)
	}
}

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
