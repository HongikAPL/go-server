package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	crand "crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/pquerna/otp/totp"
)

type SigninResponseDto struct {
	Key  []byte `json:"key"`
	Seed int64  `json:"seed"`
}

type SeedResponseDto struct {
	Seed int64 `json:"seed"`
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
	folderPath    = "./nfs_shared"
)

var (
	globalSeed int64
)

func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func binaryRead(seed interface{}) error {
	return binary.Read(crand.Reader, binary.BigEndian, seed)
}

func generateRandomSeed() (int64, error) {
	var seed int64
	err := binaryRead(&seed)
	setGlobalSeed(seed)
	return seed, err
}

func setGlobalSeed(seed int64) {
	globalSeed = seed
	fmt.Println("Current Seed Code:", globalSeed)
}

func generateRandomSecretKey() ([]byte, error) {
	randSource := mrand.NewSource(globalSeed)
	randInstance := mrand.New(randSource)
	randomSecretKey := make([]byte, 32)

	for i := 0; i < len(randomSecretKey); i++ {
		randomSecretKey[i] = byte(randInstance.Intn(256))
	}

	return randomSecretKey, nil
}

func generateOTP(secretKeyBytes []byte) (string, error) {
	// otpURL, err := totp.Generate(totp.GenerateOpts{
	// 	Issuer:      "App Name",
	// 	AccountName: "test@example.com",
	// 	Secret:      secretKeyBytes,
	// })
	// if err != nil {
	// 	fmt.Println("Error generating TOTP URL:", err)
	// 	return "", err
	// }

	// fmt.Println("TOTP URL:\n", otpURL.URL())
	secretKey := base32.StdEncoding.EncodeToString(secretKeyBytes)
	secretKey = secretKey[:32]

	fixedTime := time.Unix((time.Now().Unix()/30)*30, 0)

	totp, err := totp.GenerateCode(secretKey, fixedTime)
	if err != nil {
		fmt.Println("Error generating TOTP code:", err)
		return "", err
	}

	return totp, nil
}

func encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

func encryptFilesInFolder(key []byte, otp string) error {
	files, err := ioutil.ReadDir(folderPath)
	if err != nil {
		return err
	}

	for _, file := range files {
		filePath := filepath.Join(folderPath, file.Name())
		data, err := ioutil.ReadFile(filePath)
		if err != nil {
			return err
		}

		encryptedData, err := encrypt(data, key)
		if err != nil {
			return err
		}

		newFolderPath := filepath.Join(folderPath, "/", otp)
		if err := os.Mkdir(newFolderPath, os.ModePerm); err != nil {
			return err
		}

		newFilePath := filepath.Join(newFolderPath, "/", file.Name())
		err = ioutil.WriteFile(newFilePath, encryptedData, os.ModePerm)
		if err != nil {
			return err
		}
	}

	return nil
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

func signinHandler(c echo.Context) error {
	var user User

	if err := c.Bind(&user); err != nil {
		return c.JSON(http.StatusBadRequest, "Invalid request payload")
	}

	if user.Username == validUsername && user.Password == validPassword {
		seed, err := generateRandomSeed()
		if err != nil {
			return c.JSON(http.StatusBadRequest, "Failed to generate time-based Seed")
		}

		secretKeyBytes, err := generateRandomSecretKey()
		if err != nil {
			return c.JSON(http.StatusBadRequest, "Failed to generate secretKeyBytes")
		}

		// totp, err := generateOTP(secretKeyBytes)
		// if err != nil {
		// 	return c.JSON(http.StatusBadRequest, "Failed to generate time-based OTP")
		// }

		// fmt.Println("Current TOTP Code:", totp)

		// if err := encryptFilesInFolder(secretKeyBytes, totp); err != nil {
		// 	return c.JSON(http.StatusBadRequest, "Error encryption files")
		// }

		signinResponseDto := SigninResponseDto{Key: secretKeyBytes, Seed: seed}
		return c.JSON(http.StatusOK, ApiResponse{Status: http.StatusOK, Data: signinResponseDto, Message: "Authentication Success"})
	} else {
		return echo.NewHTTPError(http.StatusBadRequest, "Authentication failed. Invalid username or password")
	}
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

func generateNfsUrl() (string, error) {
	serverIP, err := getServerIPAddress()
	if err != nil {
		return "", err
	}

	return serverIP + ":/mnt/nfs_share", nil
}

func verifyHandler(c echo.Context) error {
	nfsUrl, err := generateNfsUrl()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err)
	}

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

	e.POST("/api/auth/signin", signinHandler)
	e.GET("/api/auth/verify", verifyHandler, verifyTokenMiddleware)

	e.Logger.Fatal(e.Start(":8080"))
}
