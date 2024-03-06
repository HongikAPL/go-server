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
	"time"

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

type VerifyRequestDto struct {
	Otp string `json:"otp"`
}

const (
	validUsername = "test"
	validPassword = "test"
	folderPath    = "./nfs_shared"
)

var (
	globalSeed      int64
	globalSecretKey []byte
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
	fmt.Println("seed :", seed)
}

func generateRandomSecretKey() ([]byte, error) {
	randSource := mrand.NewSource(globalSeed)
	randInstance := mrand.New(randSource)
	randomSecretKey := make([]byte, 32)

	for i := 0; i < len(randomSecretKey); i++ {
		randomSecretKey[i] = byte(randInstance.Intn(256))
	}
	fmt.Println("randomSecretKey :", randomSecretKey)
	globalSecretKey = randomSecretKey

	return randomSecretKey, nil
}

func generateOTP() (string, error) {
	secretKey := base32.StdEncoding.EncodeToString(globalSecretKey)
	secretKey = secretKey[:32]

	fixedTime := time.Unix((time.Now().Unix()/30)*30, 0)

	totp, err := totp.GenerateCode(secretKey, fixedTime)
	if err != nil {
		fmt.Println("Error generating TOTP code:", err)
		return "", err
	}

	fmt.Println("totp :", totp)

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

		signinResponseDto := SigninResponseDto{Key: secretKeyBytes, Seed: seed}
		return c.JSON(http.StatusOK, ApiResponse{Status: http.StatusOK, Data: signinResponseDto, Message: "Authentication Success"})
	} else {
		return echo.NewHTTPError(http.StatusBadRequest, "Authentication failed. Invalid username or password")
	}
}

func verifyMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		var verifyRequestDto VerifyRequestDto

		if err := c.Bind(&verifyRequestDto); err != nil {
			return c.JSON(http.StatusBadRequest, "Invalid request payload")
		}

		totp, err := generateOTP()
		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token")
		}

		if totp != verifyRequestDto.Otp {
			return echo.NewHTTPError(http.StatusUnauthorized, "Token is not valid")
		}

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
	e.GET("/api/auth/verify", verifyHandler, verifyMiddleware)

	e.Logger.Fatal(e.Start(":8080"))
}
