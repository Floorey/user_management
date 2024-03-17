package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// User struct
type User struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"-"`
	Role     string `json:"role"`
}

var jwtKey = []byte("secret_key")
var db *sql.DB // Globale Datenbankverbindung

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
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
	_, err = db.Exec("INSERT INTO users1 (username, email, password, role) VALUES ($1, $2, $3, $4)", user.Username, user.Email, hashedPassword, user.Role)

	if err != nil {
		return err
	}

	return nil
}

// getUserFromDB retrieves a user from the database by username
func getUserFromDB(username string) (User, error) {
	var user User
	row := db.QueryRow("SELECT username, email, role FROM users1 WHERE username = $1", username)
	err := row.Scan(&user.Username, &user.Email, &user.Role)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

// authenticateUser authenticates a user by verifying their username and password
func authenticateUser(username, password string) (bool, error) {
	var hashedPassword string
	err := db.QueryRow("SELECT password FROM users1 WHERE username = $1", username).Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			// User not found
			return false, nil
		}
		// Another error occurred
		return false, err
	}

	// Check if the password matches
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		// Wrong password
		return false, nil
	}

	// Authentication successful
	return true, nil
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

// RegisterUserHandler handles the registration of new users
func RegisterUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = addUserToDB(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// LoginHandler handles user login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	authOK, err := authenticateUser(user.Username, user.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !authOK {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	tokenString, err := generateToken(user.Username, user.Role)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// GetUserHandler handles retrieving user information
func GetUserHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	user, err := getUserFromDB(username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
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

	// HTTP server setup
	http.HandleFunc("/register", RegisterUserHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/user", GetUserHandler)

	log.Println("Server is running on :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
