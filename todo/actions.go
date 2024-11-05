package todo

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Task struct {
	ID          uint `gorm:"primaryKey"`
	Author      string
	Task        string
	Urgency     string
	Completed   bool
	CreatedAt   time.Time
	CompletedAt time.Time
}

var db *gorm.DB

var (
	ErrTaskNotFound     = errors.New("task not found")
	ErrPermissionDenied = errors.New("permission denied")
)

func InitDB() error {
	var err error
	db, err = gorm.Open(sqlite.Open("tasks.db"), &gorm.Config{})
	if err != nil {
		return err
	}

	return db.AutoMigrate(&Task{})
}

func AddTask(author, task, urgency string) (Task, error) {
	newTask := Task{
		Author:    author,
		Task:      task,
		Urgency:   urgency,
		Completed: false,
		CreatedAt: time.Now(),
	}

	if err := db.Create(&newTask).Error; err != nil {
		return newTask, err
	}

	return newTask, nil
}

func CompleteTask(id int, author string) (Task, error) {
	var task Task

	if err := db.First(&task, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return task, fmt.Errorf("%w: task with ID %d", ErrTaskNotFound, id)
		}
		return task, fmt.Errorf("unexpected error: %v", err) // Handle unexpected errors
	}

	if task.Author != author {
		return task, fmt.Errorf("%w: you do not have permission to mark task with ID %d complete", ErrPermissionDenied, id)
	}

	task.Completed = true
	if err := db.Save(&task).Error; err != nil {
		return task, err
	}

	return task, nil
}

func DeleteTask(id int, author string) error {
	var task Task

	if err := db.First(&task, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("%w: task with ID %d", ErrTaskNotFound, id)
		}
		return fmt.Errorf("unexpected error: %v", err) // Return any other unexpected errors
	}

	if task.Author != author {
		return fmt.Errorf("%w: you do not have permission to delete task with ID %d", ErrPermissionDenied, id)
	}

	if err := db.Delete(&task).Error; err != nil {
		return err
	}

	return nil
}

func ListTasks(author string) []Task {
	var tasks []Task
	db.Where("Author=?", author).Find(&tasks)

	return tasks
}

// TODO: delete, mark complete
