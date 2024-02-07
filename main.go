package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

const (
	validUsername = "test"
	validPassword = "test"
)

func loginHandler(rw http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost{
		var user User
		json.NewDecoder(r.Body).Decode(&user)

		if user.Username == validUsername && user.Password == validPassword {
			fmt.Fprint(rw, "Authentication Success")
		} else {
			http.Error(rw, "Authentication failed. Invalid username or password", http.StatusBadRequest)
		}
	} else {
		http.Error(rw, "Method 는 Post 입니다.", http.StatusMethodNotAllowed)
	}
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/auth/login", loginHandler)
	fmt.Println("Server is running on http://localhost:8080")
	http.ListenAndServe(":8080", mux) // mux : handler Handler
}
