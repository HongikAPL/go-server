package main

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type ResponseDto struct {
	Result string `json:"result"`
}

type Response struct {
	Status int `json:"status"`
	Data interface{} `json:"data"`
	Message string `json:"message"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

const (
	validUsername = "test"
	validPassword = "test"
)

func loginHandler(c echo.Context) error {
	var user User
	if err := c.Bind(&user); err != nil {
		return c.JSON(http.StatusBadRequest, "Invalid request payload")
	}

	if user.Username == validUsername && user.Password == validPassword {
		responseDto := ResponseDto{Result : "성공"}
		return c.JSON(http.StatusOK, Response{Status: http.StatusOK, Data: responseDto, Message: "Authentication Success"})
	} else {
		return echo.NewHTTPError(http.StatusBadRequest, "Authentication failed. Invalid username or password")
	}
}

func main() {
	e := echo.New()

	// 미들웨어 설정
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// 라우트 설정
	e.POST("/api/auth/login", loginHandler)

	// 서버 시작
	fmt.Println("Server is running on http://localhost:8080")
	e.Start(":8080")
}
