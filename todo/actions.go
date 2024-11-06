package todo

import (
	"errors"
	"fmt"
	"time"

	"github.com/bedminer1/todo/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var (
	ErrTaskNotFound     = errors.New("task not found")
	ErrPermissionDenied = errors.New("permission denied")
)

type TodoService struct {
	DB *gorm.DB
}

func NewTodoService(db *gorm.DB) *TodoService {
	return &TodoService{DB: db}
}

func (t *TodoService) AddTask(author, task, urgency string) (models.Task, error) {
	newTask := models.Task{
		ID:        uuid.NewString(),
		Author:    author,
		Task:      task,
		Urgency:   urgency,
		Completed: false,
		CreatedAt: time.Now(),
	}

	if err := t.DB.Create(&newTask).Error; err != nil {
		return newTask, err
	}

	return newTask, nil
}

func (t *TodoService) CompleteTask(id int, author string) (models.Task, error) {
	var task models.Task

	if err := t.DB.First(&task, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return task, fmt.Errorf("%w: task with ID %d", ErrTaskNotFound, id)
		}
		return task, fmt.Errorf("unexpected error: %v", err) // Handle unexpected errors
	}

	if task.Author != author {
		return task, fmt.Errorf("%w: you do not have permission to mark task with ID %d complete", ErrPermissionDenied, id)
	}

	task.Completed = true
	if err := t.DB.Save(&task).Error; err != nil {
		return task, err
	}

	return task, nil
}

func (t *TodoService) DeleteTask(id int, author string) error {
	var task models.Task

	if err := t.DB.First(&task, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("%w: task with ID %d", ErrTaskNotFound, id)
		}
		return fmt.Errorf("unexpected error: %v", err) // Return any other unexpected errors
	}

	if task.Author != author {
		return fmt.Errorf("%w: you do not have permission to delete task with ID %d", ErrPermissionDenied, id)
	}

	if err := t.DB.Delete(&task).Error; err != nil {
		return err
	}

	return nil
}

func (t *TodoService) ListTasks(author string) []models.Task {
	var (
		tasks []models.Task
		user models.User
	)
	t.DB.Where("username = ?", author).First(&user)
	t.DB.Model(&models.Task{}).Joins("LEFT JOIN task_viewers ON task_viewers.task_id = tasks.id").
	Where("tasks.author = ? OR task_viewers.user_id = ?", user.Username, user.ID).
	Find(&tasks)
	
	return tasks
}
