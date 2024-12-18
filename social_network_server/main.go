package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// User struct for GORM model
type User struct {
	ID    uint   `gorm:"primaryKey"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// Request and Response structures
type RequestData struct {
	Message string `json:"message"`
}

type ResponseData struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// Global database instance
var db *gorm.DB

// Initialize database connection
func initDB() {
	var err error
	// Update credentials according to your PostgreSQL setup
	dsn := "host=localhost user=abukhassymkhydyrbayev password=admin dbname=social_pub port=5432 sslmode=disable"
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Could not connect to the database: %v", err)
	}
	fmt.Println("Connected to the database")

	// Auto-migrate User table
	db.AutoMigrate(&User{})
}

// Create a new user
func createUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Save user to database
	if err := db.Create(&user).Error; err != nil {
		http.Error(w, "Could not create user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// Get a user by ID
func getUserByIDHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	// Extract ID from query
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing 'id' parameter", http.StatusBadRequest)
		return
	}

	var user User
	if err := db.First(&user, id).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// Update a user by ID
func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	// Extract ID from query
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing 'id' parameter", http.StatusBadRequest)
		return
	}

	var user User
	if err := db.First(&user, id).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Parse request body for updates
	var updatedData User
	if err := json.NewDecoder(r.Body).Decode(&updatedData); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Update fields
	db.Model(&user).Updates(updatedData)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// Delete a user by ID
func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	// Extract ID from query
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing 'id' parameter", http.StatusBadRequest)
		return
	}

	// Delete user
	if err := db.Delete(&User{}, id).Error; err != nil {
		http.Error(w, "Could not delete user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ResponseData{"success", "User deleted"})
}

const maxRequestBodySize = 1 << 20 // 1MB limit

// POST request handler
func postHandler(w http.ResponseWriter, r *http.Request) {
	// Allow only POST method
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		response := ResponseData{"fail", "Only POST method is allowed"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Set response header
	w.Header().Set("Content-Type", "application/json")

	// Limit request body size to prevent abuse
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	// Check if request body is empty
	if r.Body == http.NoBody {
		w.WriteHeader(http.StatusBadRequest)
		response := ResponseData{"fail", "Request body cannot be empty"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Parse JSON body and detect unexpected fields
	var requestData map[string]interface{}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // Disallow extra/unknown fields
	err := decoder.Decode(&requestData)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		response := ResponseData{"fail", "Invalid JSON or unexpected fields"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check if "message" key exists
	message, ok := requestData["message"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		response := ResponseData{"fail", "Message field is required"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Ensure "message" value is a string (empty string is allowed)
	messageStr, isString := message.(string)
	if !isString {
		w.WriteHeader(http.StatusBadRequest)
		response := ResponseData{"fail", "Message field must be a string"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Print the valid message to server console
	fmt.Printf("Received message: %s\n", messageStr)

	// Send success response
	response := ResponseData{"success", "Data successfully received"}
	json.NewEncoder(w).Encode(response)
}

const maxQueryParamSize = 1024 // 1KB limit for query string size

// GET request handler
func getHandler(w http.ResponseWriter, r *http.Request) {
	// Allow only GET method
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set response header
	w.Header().Set("Content-Type", "application/json")

	// Check query string size
	queryString := r.URL.RawQuery
	if len(queryString) > maxQueryParamSize {
		http.Error(w, "Query string size exceeds limit", http.StatusRequestEntityTooLarge)
		return
	}

	// Parse and log query parameters
	queryParams := r.URL.Query()
	if len(queryParams) == 0 {
		fmt.Println("No query parameters provided")
	} else {
		fmt.Println("Query Parameters:", queryParams)
	}

	// Validate "message" query parameter
	msg := queryParams.Get("message")
	if strings.TrimSpace(msg) == "" {
		w.WriteHeader(http.StatusBadRequest)
		response := ResponseData{"fail", "Missing 'message' query parameter"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check message length
	if len(msg) > 256 {
		w.WriteHeader(http.StatusBadRequest)
		response := ResponseData{"fail", "'message' parameter is too long"}
		json.NewEncoder(w).Encode(response)
		return
	}

	fmt.Println("Query parameter 'message':", msg)

	// Send success response
	response := ResponseData{"success", "GET request received"}
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Println("Error encoding JSON response:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// Handler to retrieve all users from the database
func getUsersHandler(w http.ResponseWriter, r *http.Request) {
	// Allow only GET method
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	// Retrieve users from the database
	var users []User
	if err := db.Find(&users).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		response := ResponseData{"fail", "Could not retrieve users"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Send users as JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func main() {
	// Initialize the database
	initDB()

	// Serve static files
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Routes
	http.HandleFunc("/post", postHandler)
	http.HandleFunc("/get", getHandler)
	http.HandleFunc("/users", getUsersHandler)

	// CRUD Routes for User
	http.HandleFunc("/user/create", createUserHandler) // POST - Create a new user
	http.HandleFunc("/user/get", getUserByIDHandler)   // GET - Get a user by ID
	http.HandleFunc("/user/update", updateUserHandler) // PUT - Update a user by ID
	http.HandleFunc("/user/delete", deleteUserHandler) // DELETE - Delete a user by ID

	// Start the server
	fmt.Println("Server is running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
