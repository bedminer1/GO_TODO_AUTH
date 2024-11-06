package models

import "time"

type BlacklistedToken struct {
	ID         string    `gorm:"primaryKey"`
	User       string    `gorm:"not null"`
	Expiration time.Time `gorm:"not null"`
}

type User struct {
	ID            string `gorm:"primaryKey"`
	Username      string `gorm:"unique; not null"`
	Password      string `gorm:"not null"`
	ActiveJWT     string
	ViewableTasks []*Task `gorm:"many2many:task_viewers;"`
}

type Task struct {
	ID          string `gorm:"primaryKey"`
	Author      string
	AuthorID    string
	Task        string
	Urgency     string
	Completed   bool
	CreatedAt   time.Time
	CompletedAt time.Time
	Viewers     []*User `gorm:"many2many:task_viewers;"`
}

type TaskViewer struct {
	TaskID  string `gorm:"primaryKey"`
	UserID  string `gorm:"primaryKey"`
	Task    Task   `gorm:"foreignKey:TaskID"`
	User    User   `gorm:"foreignKey:UserID"`
}