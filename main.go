package main

import (
	"github.com/an1l4/jwt-gin-gorm/controllers"
	"github.com/an1l4/jwt-gin-gorm/initializers"
	"github.com/an1l4/jwt-gin-gorm/middleware"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDatabase()
}

func main() {
	r := gin.Default()

	r.POST("/signup", controllers.SignUp)
	r.POST("/login", controllers.Login)
	r.GET("/validate", middleware.RequireAuth, controllers.Validate)
	r.Run()
}
