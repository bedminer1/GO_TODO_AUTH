package todo

import (
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Task struct {
	ID          uint `gorm:"primaryKey"`
	Task        string
	Urgency     string
	Completed   bool
	CreatedAt   time.Time
	CompletedAt time.Time
}

func AddUser(task, urgency string) (Task, error) {
	newTask := Task {
		Task: task,
		Urgency: urgency,
		Completed: false,
		CreatedAt: time.Now(),
	}

	db, err := gorm.Open(sqlite.Open("tasks.db"), &gorm.Config{})
	if err != nil {
		return newTask, err
	}

	if err := db.AutoMigrate(&Task{}); err != nil {
		return newTask, err
	}

	if err := db.Create(&newTask).Error; err != nil {
		return newTask, err
	}

	return newTask, nil
}
