package todo

import (
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

func CompleteTask(id int) Task {
	var task Task

	db.Where("ID=?", id).First(&task)
	task.Completed = true
	db.Save(&task)

	return task
}

func DeleteTask(id int) Task {
	var task Task
	db.Where("ID=?", id).First(&task)
	db.Delete(&task)

	return task
}

func ListTasks(author string) []Task {
	var tasks []Task
	db.Where("Author=?", author).Find(&tasks)

	return tasks
}

// TODO: delete, mark complete
