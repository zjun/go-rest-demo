package main

import (
	"go-rest-demo/api"

	"github.com/gin-gonic/gin"

	"go-rest-demo/middleware/jwt"
)

func main() {
	r := gin.Default()
	r.POST("/login", api.Login)

	taR := r.Group("/data")
	taR.Use(jwt.JWTAuth())
	{
		taR.GET("/jwtDemo", api.JwtDemo)
	}
	r.Run(":8080")

}
