package api

import (
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"

	myjwt "go-rest-demo/middleware/jwt"
)

const (
	user     = "user"
	password = "passw0rd"
)

// 认证信息
type AuthInfo struct {
	// 手机号
	User string `json:"user"`
	// 密码
	Password string `json:"pwd"`
}

// AuthResult 认证结果
type AuthResult struct {
	Token string `json:"token"`
}

// Login 登录
func Login(c *gin.Context) {
	var loginReq AuthInfo
	if c.BindJSON(&loginReq) == nil {
		isPass := loginCheck(loginReq)
		if isPass {
			generateToken(c, loginReq)
		} else {
			c.JSON(http.StatusOK, gin.H{
				"status": -1,
				"msg":    "Token验证失败",
			})
		}
	} else {
		c.JSON(http.StatusOK, gin.H{
			"status": -1,
			"msg":    "json 解析失败",
		})
	}
}

// LoginCheck 登录验证
func loginCheck(loginReq AuthInfo) bool {
	resultBool := false
	if loginReq.User == user && loginReq.Password == password {
		resultBool = true
	}

	return resultBool
}

// 生成令牌
func generateToken(c *gin.Context, authInfo AuthInfo) {
	j := &myjwt.JWT{
		[]byte("JohnZhu"),
	}
	claims := myjwt.CustomClaims{
		authInfo.User,
		authInfo.Password,
		jwt.StandardClaims{
			NotBefore: int64(time.Now().Unix() - 1000), // 签名生效时间
			ExpiresAt: int64(time.Now().Unix() + 3600), // 过期时间 一小时
			Issuer:    "JohnZhu",                       //签名的发行者
		},
	}

	token, err := j.CreateToken(claims)

	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": -1,
			"msg":    err.Error(),
		})
		return
	}

	log.Println(token)

	data := AuthResult{
		Token: token,
	}
	c.JSON(http.StatusOK, gin.H{
		"status": 0,
		"msg":    "登录成功！",
		"data":   data,
	})
	return
}

func JwtDemo(c *gin.Context) {
	claims := c.MustGet("claims").(*myjwt.CustomClaims)
	if claims != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": 0,
			"msg":    "token有效",
			"data":   claims,
		})
	}
}
