package controllers

import (
	"net/http"
	"os"
	"time"

	"github.com/an1l4/jwt-gin-gorm/initializers"
	"github.com/an1l4/jwt-gin-gorm/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func SignUp(ctx *gin.Context) {
	//get the email and password from body

	var body struct {
		Email    string
		Password string
	}

	if ctx.Bind(&body) != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "failed to read body",
		})
		return
	}

	//hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password",
		})
		return
	}

	//create the user or save user in db

	user := models.User{Email: body.Email, Password: string(hash)}
	result := initializers.DB.Create(&user)

	if result.Error != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user",
		})
		return
	}

	//Respond

	ctx.JSON(http.StatusOK, gin.H{})

}

func Login(ctx *gin.Context) {
	//get the email and password

	var body struct {
		Email    string
		Password string
	}

	if ctx.Bind(&body) != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "failed to read body",
		})
		return
	}

	//check in db
	var user models.User
	initializers.DB.First(&user, "email=?", body.Email)

	if user.ID == 0 {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	//compare
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	//generate jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to generate token",
		})
		return
	}

	//send it back to client
	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)

	ctx.JSON(http.StatusOK, gin.H{})

}
//middleware

func Validate(ctx *gin.Context) {
	user,_:=ctx.Get("user")
	ctx.JSON(http.StatusOK,gin.H{
		"message":user,
	})
}
