package middleware

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/an1l4/jwt-gin-gorm/initializers"
	"github.com/an1l4/jwt-gin-gorm/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

//middleware
func RequireAuth(ctx *gin.Context) {
	//get the cookie from req
	tokenString, err := ctx.Cookie("Authorization")

	if err != nil {
		ctx.AbortWithStatus(http.StatusUnauthorized)
	}

	//Decode and validate it
	// Parse takes the token string and a function for looking up the key. The latter is especially
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("SECRET")), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		//check the exp
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			ctx.AbortWithStatus(http.StatusUnauthorized)

		}

		//find the user with sub
		var user models.User
		initializers.DB.First(&user, claims["sub"])

		if user.ID == 0 {
			ctx.AbortWithStatus(http.StatusUnauthorized)
		}

		//attach req

		ctx.Set("user", user)
		//continue
		ctx.Next()

	} else {
		ctx.AbortWithStatus(http.StatusUnauthorized)
	}

}
