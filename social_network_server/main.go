package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// User struct to match the new database schema
type User struct {
	UserID    uint      `gorm:"primaryKey;column:user_id" json:"user_id"`
	UserName  string    `gorm:"column:user_name" json:"user_name"`
	UserEmail string    `gorm:"column:user_email;uniqueIndex" json:"user_email"`
	CreatedAt time.Time `gorm:"column:created_at" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at" json:"updated_at"`
}

// Ensure the table name matches the database schema
func (User) TableName() string {
	return "users"
}

// Global database instance
var db *gorm.DB

type ResponseData struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

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

	// AutoMigrate to ensure the users table exists with the correct schema
	err = db.AutoMigrate(&User{})
	if err != nil {
		log.Fatalf("Could not migrate database: %v", err)
	}
}

// Create or Update User Handler
func userHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, x-ijt, X-Requested-With, Authorization")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	// Handle preflight requests
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	switch r.Method {
	case http.MethodPost:
		createUser(w, r)
	case http.MethodGet:
		getAllUsers(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Create User
func createUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		// Ensure JSON error response
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ResponseData{
			Status:  "error",
			Message: "Invalid request body",
		})
		return
	}

	// Validate input
	if user.UserName == "" || user.UserEmail == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ResponseData{
			Status:  "error",
			Message: "Name and email are required",
		})
		return
	}

	// Validate email
	if !isValidEmail(user.UserEmail) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	// Set timestamps
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	// Create user in database
	result := db.Create(&user)
	if result.Error != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ResponseData{
			Status:  "error",
			Message: fmt.Sprintf("Could not create user: %v", result.Error),
		})
		return
	}

	// Respond with created user
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(ResponseData{
		Status:  "success",
		Message: "User created successfully",
		Data:    user,
	})
}

// Get All Users
func getAllUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var users []User
	result := db.Find(&users)
	if result.Error != nil {
		http.Error(w, fmt.Sprintf("Could not retrieve users: %v", result.Error), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(users)
}

// Delete User
func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight requests
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract ID from query or body
	var deleteID uint
	var err error

	// Try to get ID from query parameter first
	idStr := r.URL.Query().Get("id")
	if idStr != "" {
		var id uint64
		id, err = strconv.ParseUint(idStr, 10, 32)
		deleteID = uint(id)
	} else {
		// If not in query, try to get from request body
		var requestBody map[string]uint
		err = json.NewDecoder(r.Body).Decode(&requestBody)
		if err == nil {
			deleteID = requestBody["user_id"]
		}
	}

	if err != nil || deleteID == 0 {
		http.Error(w, "Invalid or missing user ID", http.StatusBadRequest)
		return
	}

	// Perform deletion
	result := db.Delete(&User{}, deleteID)
	if result.Error != nil {
		http.Error(w, fmt.Sprintf("Could not delete user: %v", result.Error), http.StatusInternalServerError)
		return
	}

	// Check if any row was actually deleted
	if result.RowsAffected == 0 {
		http.Error(w, "No user found with the given ID", http.StatusNotFound)
		return
	}

	// Respond with success
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ResponseData{
		Status:  "success",
		Message: "User deleted successfully",
	})
}

// CreateUser creates a new user in the database
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

	// Set created_at and updated_at to current time
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	// Validate email
	if !isValidEmail(user.UserEmail) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	// Save user to database
	result := db.Create(&user)
	if result.Error != nil {
		http.Error(w, fmt.Sprintf("Could not create user: %v", result.Error), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

// GetUser retrieves a user by ID
func getUserHandler(w http.ResponseWriter, r *http.Request) {
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
	result := db.First(&user, id)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			http.Error(w, fmt.Sprintf("Error retrieving user: %v", result.Error), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// GetAllUsers retrieves all users from the database
func getAllUsersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	var users []User
	result := db.Find(&users)
	if result.Error != nil {
		http.Error(w, fmt.Sprintf("Could not retrieve users: %v", result.Error), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// Update User
func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight requests
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decode request body
	var updateData struct {
		UserID    uint   `json:"user_id"`
		UserName  string `json:"user_name,omitempty"`
		UserEmail string `json:"user_email,omitempty"`
	}
	err := json.NewDecoder(r.Body).Decode(&updateData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate user ID
	if updateData.UserID == 0 {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	// Find existing user
	var user User
	result := db.First(&user, updateData.UserID)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			http.Error(w, fmt.Sprintf("Error finding user: %v", result.Error), http.StatusInternalServerError)
		}
		return
	}

	// Update fields
	if updateData.UserName != "" {
		user.UserName = updateData.UserName
	}
	if updateData.UserEmail != "" {
		// Validate email if provided
		if !isValidEmail(updateData.UserEmail) {
			http.Error(w, "Invalid email format", http.StatusBadRequest)
			return
		}
		user.UserEmail = updateData.UserEmail
	}

	// Update timestamp
	user.UpdatedAt = time.Now()

	// Save updates
	result = db.Save(&user)
	if result.Error != nil {
		http.Error(w, fmt.Sprintf("Could not update user: %v", result.Error), http.StatusInternalServerError)
		return
	}

	// Respond with updated user
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ResponseData{
		Status:  "success",
		Message: "User updated successfully",
		Data:    user,
	})
}

// DeleteUser deletes a user by ID
//func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
//	if r.Method != http.MethodDelete {
//		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
//		return
//	}
//
//	// Extract ID from query
//	id := r.URL.Query().Get("id")
//	if id == "" {
//		http.Error(w, "Missing 'id' parameter", http.StatusBadRequest)
//		return
//	}
//
//	// Delete user
//	result := db.Delete(&User{}, id)
//	if result.Error != nil {
//		http.Error(w, fmt.Sprintf("Could not delete user: %v", result.Error), http.StatusInternalServerError)
//		return
//	}
//
//	// Check if any row was actually deleted
//	if result.RowsAffected == 0 {
//		http.Error(w, "No user found with the given ID", http.StatusNotFound)
//		return
//	}
//
//	w.Header().Set("Content-Type", "application/json")
//	json.NewEncoder(w).Encode(map[string]string{
//		"status":  "success",
//		"message": "User deleted successfully",
//	})
//}

// Helper function to validate email
func isValidEmail(email string) bool {
	// Basic email validation
	if len(email) < 3 || len(email) > 254 {
		return false
	}

	// Check for @ and .
	atIndex := strings.Index(email, "@")
	dotIndex := strings.LastIndex(email, ".")

	return atIndex > 0 &&
		dotIndex > atIndex &&
		dotIndex < len(email)-1
}

//const maxRequestBodySize = 1 << 20 // 1MB limit
//
//// POST request handler
//func postHandler(w http.ResponseWriter, r *http.Request) {
//	// Allow only POST method
//	if r.Method != http.MethodPost {
//		w.WriteHeader(http.StatusMethodNotAllowed)
//		response := ResponseData{"fail", "Only POST method is allowed"}
//		json.NewEncoder(w).Encode(response)
//		return
//	}
//
//	// Set response header
//	w.Header().Set("Content-Type", "application/json")
//
//	// Limit request body size to prevent abuse
//	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
//
//	// Check if request body is empty
//	if r.Body == http.NoBody {
//		w.WriteHeader(http.StatusBadRequest)
//		response := ResponseData{"fail", "Request body cannot be empty"}
//		json.NewEncoder(w).Encode(response)
//		return
//	}
//
//	// Parse JSON body and detect unexpected fields
//	var requestData map[string]interface{}
//	decoder := json.NewDecoder(r.Body)
//	decoder.DisallowUnknownFields() // Disallow extra/unknown fields
//	err := decoder.Decode(&requestData)
//	if err != nil {
//		w.WriteHeader(http.StatusBadRequest)
//		response := ResponseData{"fail", "Invalid JSON or unexpected fields"}
//		json.NewEncoder(w).Encode(response)
//		return
//	}
//
//	// Check if "message" key exists
//	message, ok := requestData["message"]
//	if !ok {
//		w.WriteHeader(http.StatusBadRequest)
//		response := ResponseData{"fail", "Message field is required"}
//		json.NewEncoder(w).Encode(response)
//		return
//	}
//
//	// Ensure "message" value is a string (empty string is allowed)
//	messageStr, isString := message.(string)
//	if !isString {
//		w.WriteHeader(http.StatusBadRequest)
//		response := ResponseData{"fail", "Message field must be a string"}
//		json.NewEncoder(w).Encode(response)
//		return
//	}
//
//	// Print the valid message to server console
//	fmt.Printf("Received message: %s\n", messageStr)
//
//	// Send success response
//	response := ResponseData{"success", "Data successfully received"}
//	json.NewEncoder(w).Encode(response)
//}
//
//const maxQueryParamSize = 1024 // 1KB limit for query string size
//
//// GET request handler
//func getHandler(w http.ResponseWriter, r *http.Request) {
//	// Allow only GET method
//	if r.Method != http.MethodGet {
//		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
//		return
//	}
//
//	// Set response header
//	w.Header().Set("Content-Type", "application/json")
//
//	// Check query string size
//	queryString := r.URL.RawQuery
//	if len(queryString) > maxQueryParamSize {
//		http.Error(w, "Query string size exceeds limit", http.StatusRequestEntityTooLarge)
//		return
//	}
//
//	// Parse and log query parameters
//	queryParams := r.URL.Query()
//	if len(queryParams) == 0 {
//		fmt.Println("No query parameters provided")
//	} else {
//		fmt.Println("Query Parameters:", queryParams)
//	}
//
//	// Validate "message" query parameter
//	msg := queryParams.Get("message")
//	if strings.TrimSpace(msg) == "" {
//		w.WriteHeader(http.StatusBadRequest)
//		response := ResponseData{"fail", "Missing 'message' query parameter"}
//		json.NewEncoder(w).Encode(response)
//		return
//	}
//
//	// Check message length
//	if len(msg) > 256 {
//		w.WriteHeader(http.StatusBadRequest)
//		response := ResponseData{"fail", "'message' parameter is too long"}
//		json.NewEncoder(w).Encode(response)
//		return
//	}
//
//	fmt.Println("Query parameter 'message':", msg)
//
//	// Send success response
//	response := ResponseData{"success", "GET request received"}
//	err := json.NewEncoder(w).Encode(response)
//	if err != nil {
//		log.Println("Error encoding JSON response:", err)
//		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
//	}
//}

const maxRequestBodySize = 1 << 20 // 1MB limit
const maxQueryParamSize = 1024     // 1KB limit for query string size

// POST request handler
func postHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight requests
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Allow only POST method
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		response := ResponseData{Status: "fail", Message: "Only POST method is allowed"}
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
		response := ResponseData{Status: "fail", Message: "Request body cannot be empty"}
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
		response := ResponseData{Status: "fail", Message: "Invalid JSON or unexpected fields"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check if "message" key exists
	message, ok := requestData["message"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		response := ResponseData{Status: "fail", Message: "Message field is required"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Ensure "message" value is a string (empty string is allowed)
	messageStr, isString := message.(string)
	if !isString {
		w.WriteHeader(http.StatusBadRequest)
		response := ResponseData{Status: "fail", Message: "Message field must be a string"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Print the valid message to server console
	fmt.Printf("Received message: %s\n", messageStr)

	// Send success response
	response := ResponseData{Status: "success", Message: "Data successfully received"}
	json.NewEncoder(w).Encode(response)
}

// GET request handler
func getHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight requests
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

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
		response := ResponseData{Status: "fail", Message: "Missing 'message' query parameter"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check message length
	if len(msg) > 256 {
		w.WriteHeader(http.StatusBadRequest)
		response := ResponseData{Status: "fail", Message: "'message' parameter is too long"}
		json.NewEncoder(w).Encode(response)
		return
	}

	fmt.Println("Query parameter 'message':", msg)

	// Send success response
	response := ResponseData{Status: "success", Message: "GET request received"}
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Println("Error encoding JSON response:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, x-ijt, X-Requested-With, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func main() {
	// Initialize the database
	initDB()

	// Serve static files
	//fs := http.FileServer(http.Dir("./static"))
	//http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Routes
	http.HandleFunc("/post", postHandler)
	http.HandleFunc("/get", getHandler)

	// Wrap your handlers with the CORS middleware
	http.HandleFunc("/users", corsMiddleware(userHandler))
	http.HandleFunc("/user/create", corsMiddleware(createUserHandler))
	http.HandleFunc("/user/update", corsMiddleware(updateUserHandler))
	http.HandleFunc("/user/delete", corsMiddleware(deleteUserHandler))

	// Serve static files
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	//// User management routes
	//http.HandleFunc("/users", userHandler)
	//
	//// CRUD Routes for User
	//http.HandleFunc("/user/create", createUserHandler)
	//http.HandleFunc("/user/get", getUserHandler)
	//http.HandleFunc("/user/list", getAllUsersHandler)
	//http.HandleFunc("/user/update", updateUserHandler)
	//http.HandleFunc("/user/delete", deleteUserHandler)

	// Start the server
	fmt.Println("Server is running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
