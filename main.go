package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

// User struct
type User struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"-"`
	Role     string `json:"role"`
	Token    string `json:"token"`
}

var jwtKey = []byte("secret_key")
var db *sql.DB // Global database connection

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

// rate-Limit for user
var userRateLimit = make(map[string]*rate.Limiter)

// Middleware-Function for Rate-Limit per user
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := getUserFromToken(r)

		// check for user rate limit
		limiter, ok := userRateLimit[username]
		if !ok {
			limiter = rate.NewLimiter(rate.Limit(10), 100)
			userRateLimit[username] = limiter
		}
		if !limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// getUserFromToken extracts the username from the JWT token
func getUserFromToken(r *http.Request) string {
	tokenString := r.Header.Get("Authorization")
	tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
	if tokenString == "" {
		return "" // Rückgabe eines leeren Benutzernamens, wenn kein Token gefunden wurde
	}
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		return "" // Rückgabe eines leeren Benutzernamens im Fehlerfall oder wenn das Token ungültig ist
	}
	if claims, ok := token.Claims.(*Claims); ok {
		return claims.Username
	}
	return ""
}

func main() {
	password := os.Getenv("DB_PASSWORD")
	if password == "" {
		log.Fatal("Environment variable DB_PASSWORD not set")
	}

	// Connect to the database
	var err error
	db, err = sql.Open("postgres", "user=postgres dbname=users_go password="+password+" sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Set up HTTP handlers
	http.HandleFunc("/add-user", addUserHandler)
	http.HandleFunc("/get-user", getUserHandler)
	http.HandleFunc("/shutdown", shutdownServerHandler)

	// Start the server with rate limit middleware
	fmt.Println("Server listening on port 8080")
	log.Fatal(http.ListenAndServe(":8080", rateLimitMiddleware(http.DefaultServeMux)))
}

// hashPassword hashes the given password
func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// addUserToDB adds a new user to the database
func addUserToDB(user User) error {
	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		return err
	}

	// Generate JWT token
	tokenString, err := generateToken(user.Username, user.Role)
	if err != nil {
		return err
	}

	_, err = db.Exec("INSERT INTO users1 (username, email, password, role, token) VALUES ($1, $2, $3, $4, $5)", user.Username, user.Email, hashedPassword, user.Role, tokenString)
	if err != nil {
		return err
	}

	return nil
}

// getUserFromDB retrieves a user from the database by username
func getUserFromDB(username string) (User, error) {
	var user User
	row := db.QueryRow("SELECT username, email, role, token FROM users1 WHERE username = $1", username)
	err := row.Scan(&user.Username, &user.Email, &user.Role, &user.Token)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

// generateToken generates a JWT token for the given username
func generateToken(username, role string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		Role:     role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// addUserHandler handles adding a new user
func addUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err = addUserToDB(user)
	if err != nil {
		http.Error(w, "Failed to add user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "User successfully added to the database.")
}

// getUserHandler handles retrieving a user
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	// Get the username from the query parameter
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Username parameter is required", http.StatusBadRequest)
		return
	}

	// Query the database to get the user by username
	user, err := getUserFromDB(username)
	if err != nil {
		http.Error(w, "Failed to get user", http.StatusInternalServerError)
		return
	}

	// Encode the user object to JSON
	userJSON, err := json.Marshal(user)
	if err != nil {
		http.Error(w, "Failed to encode user data", http.StatusInternalServerError)
		return
	}

	// Write the user JSON data in the response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(userJSON)
}

// shutdownServerHandler handles shutting down the server
func shutdownServerHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Shutting down server...")
	// You can add code here to shut down the server
}
