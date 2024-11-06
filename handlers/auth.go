package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
	"github.com/bedminer1/todo/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

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
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}

	return err == nil, err
}

func cleanupExpiredTokens(db *gorm.DB) error {
	return db.Where("expiration < ?", time.Now()).Delete(&models.BlacklistedToken{}).Error
}

func encryptPassword(password string) string {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return ""
	}
	return string(hashedBytes)
}

func generateToken(username string) (string, error) {
	claims := &JwtCustomClaims{
		username,
		true,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)),
			ID:        uuid.NewString(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(SecretKey))
}

func (h *Handler) HandleLogin(c echo.Context) error {
	var user models.User
	username := c.FormValue("username")
	password := c.FormValue("password")
	// TODO: encrypt password
	encryptedPassword := encryptPassword(password)

	err := h.DB.Where("username = ? AND password = ?", username, encryptedPassword).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return echo.ErrUnauthorized
	}

	// has active jwt
	if user.ActiveJWT != "" {
		token, err := jwt.ParseWithClaims(user.ActiveJWT, &JwtCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(SecretKey), nil
		})

		if err == nil {
			if claims, ok := token.Claims.(*JwtCustomClaims); ok && token.Valid {
				if time.Until(claims.ExpiresAt.Time) > 24*time.Hour {
					return c.JSON(http.StatusOK, echo.Map{
						"token": user.ActiveJWT,
					})
				} else {
					addTokenToBlackList(claims.ID, claims.Name, claims.ExpiresAt.Time, h.DB)
				}
			}
		}
	}

	t, err := generateToken(username)
	if err != nil {
		return err
	}

	user.ActiveJWT = t
	if err := h.DB.Save(&user).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, "error saving token")
	}

	return c.JSON(http.StatusOK, echo.Map{
		"token": t,
	})
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

func (h *Handler) HandleSignup(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	confirmPassword := c.FormValue("confirmPassword")

	if password != confirmPassword {
		return fmt.Errorf("password and confirm password does not match")
	}

	err := h.DB.Where("username = ?", username).First(&models.User{}).Error
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound){
			return c.JSON(http.StatusBadRequest, "user already exists")
		}
	}

	var user models.User
	user.ID = uuid.NewString()
	user.Username = username
	user.Password = encryptPassword(password)

	t, err := generateToken(username)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "error generating token")
	}
	user.ActiveJWT = t
	if err := h.DB.Create(&user).Error; err != nil {
		fmt.Println(err)
		return c.JSON(http.StatusInternalServerError, "error saving profile")
	}

	return c.JSON(http.StatusOK, echo.Map{
		"token": t,
	})
}

// func (h *Handler) HandleGiveReadPermissions(c echo.Context) error {

// }

// func (h *Handler) HandleRemoveReadPermissions(c echo.Context) error {

// }

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
