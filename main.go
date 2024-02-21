package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
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

type VerifyResponseDto struct {
	NfsUrl string `json:"nfsUrl"`
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

func verifyTokenMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authorizationHeader := c.Request().Header.Get("Authorization")

		if authorizationHeader == "" {
			return echo.NewHTTPError(http.StatusUnauthorized, "Token not provided")
		}

		accessToken := strings.Replace(authorizationHeader, "Bearer ", "", 1)
		authTokenClaims := &AuthTokenClaims{}
		token, err := jwt.ParseWithClaims(accessToken, authTokenClaims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("There was an error")
			}
			return []byte(os.Getenv("SECRET_KEY")), nil
		})

		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token")
		}

		if !token.Valid {
			return echo.NewHTTPError(http.StatusUnauthorized, "Token is not valid")
		}

		c.Set("user", authTokenClaims)
		/* 미들웨어에서 저장한 user 사용하는 방법
		user := c.Get("user").(*AuthTokenClaims)
		user.Username, user.Name 등등 사용 가능
		*/
		return next(c)
	}
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

func getServerIPAddress() (string, error) {
	resp, err := http.Get("https://api64.ipify.org?format=text")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	ip, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(ip), nil
}

func generateNfsUrl() string {
	serverIP, err := getServerIPAddress()
	if err != nil {
		return "error_getting_ip"
	}

	return serverIP + ":/Users/younggyo/Documents/mount"
}

func generateAccessUrl(nfsUrl string) string {
	return "http://localhost:8080/mount?nfsUrl=" + nfsUrl
}

func verifyHandler(c echo.Context) error {
	nfsUrl := generateNfsUrl()
	verifyResponseDto := VerifyResponseDto{
		NfsUrl: nfsUrl,
	}

	return c.JSON(http.StatusOK, ApiResponse{Status: http.StatusOK, Data: verifyResponseDto, Message: "NFS URL 전송 성공"})
}

func main() {
	loadEnv()

	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.POST("/api/auth/signin", loginHandler)
	e.GET("/api/auth/verify", verifyHandler, verifyTokenMiddleware)

	e.Logger.Fatal(e.Start(":8080"))
}
