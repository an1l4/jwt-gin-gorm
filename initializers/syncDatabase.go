package initializers

import "github.com/an1l4/jwt-gin-gorm/models"

func SyncDatabase()  {
	DB.AutoMigrate(&models.User{})
}