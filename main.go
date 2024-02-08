package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type SigninResponseDto struct {
	AccessToken string `json:"accessToken"`
}

type ApiResponse struct {
	Status  int         `json:"status"`
	Data    interface{} `json:"data"`
	Message string      `json:"message"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthTokenClaims struct {
	TokenUUID string   `json:"tid"`
	Username  string   `json:"username"`
	Name      string   `json:"name"`
	Role      []string `json:"role"`
	jwt.StandardClaims
}

const (
	validUsername = "test"
	validPassword = "test"
)

func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func generateToken(username string) (string, error) {
	secretKey := os.Getenv("SECRET_KEY")
	expirationTime := time.Now().Add(1 * time.Hour)

	claims := AuthTokenClaims{
		TokenUUID: uuid.NewString(),
		Username:  username,
		Name:      "younggyo",
		Role:      []string{"user"},
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(secretKey))

	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func loginHandler(c echo.Context) error {
	var user User

	if err := c.Bind(&user); err != nil {
		return c.JSON(http.StatusBadRequest, "Invalid request payload")
	}

	if user.Username == validUsername && user.Password == validPassword {
		accessToken, err := generateToken(user.Username)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, "Failed to generate JWT token")
		}

		SigninResponseDto := SigninResponseDto{AccessToken: accessToken}
		return c.JSON(http.StatusOK, ApiResponse{Status: http.StatusOK, Data: SigninResponseDto, Message: "Authentication Success"})
	} else {
		return echo.NewHTTPError(http.StatusBadRequest, "Authentication failed. Invalid username or password")
	}
}

func main() {
	loadEnv()

	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.POST("/api/auth/signin", loginHandler)

	e.Logger.Fatal(e.Start(":8080"))
}
