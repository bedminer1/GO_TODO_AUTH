package models

import "time"

type BlacklistedToken struct {
	ID         string    `gorm:"primaryKey"`
	User       string    `gorm:"not null"`
	Expiration time.Time `gorm:"not null"`
}

type User struct {
	ID        string `gorm:"primaryKey"`
	Username  string `gorm:"unique; not null"`
	Password  string `gorm:"not null"`
	ActiveJWT string
}

type Task struct {
	ID          uint `gorm:"primaryKey"`
	Author      string
	Task        string
	Urgency     string
	Completed   bool
	CreatedAt   time.Time
	CompletedAt time.Time
}
