package main

import (
	"bufio"
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

	// Start the server
	fmt.Println("Server listening on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
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

// promptUserAction prompts the user for the action they want to perform
func promptUserAction() (string, error) {
	var action string
	fmt.Println("What would you like to do?")
	fmt.Println("1. Add a new user")
	fmt.Println("2. Retrieve an existing user")
	fmt.Println("3. Stop the server")
	fmt.Print("Enter your choice: ")
	reader := bufio.NewReader(os.Stdin)
	action, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	action = strings.TrimSpace(action)
	return action, nil
}

// promptUserForInput prompts the user for the user details
func promptUserForInput() (User, error) {
	var user User
	fmt.Println("Please enter the following details:")
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Username: ")
	user.Username, _ = reader.ReadString('\n')
	user.Username = strings.TrimSpace(user.Username)
	fmt.Print("Email: ")
	user.Email, _ = reader.ReadString('\n')
	user.Email = strings.TrimSpace(user.Email)
	fmt.Print("Password: ")
	user.Password, _ = reader.ReadString('\n')
	user.Password = strings.TrimSpace(user.Password)
	fmt.Print("Role: ")
	user.Role, _ = reader.ReadString('\n')
	user.Role = strings.TrimSpace(user.Role)
	return user, nil
}

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

func stopServerHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Stopping the server...")
	os.Exit(0)
}

func shutdownServerHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Shutting down the server...")
	os.Exit(0)
}

// Handle function for retrieving a user
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
