package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jordan-wright/email"
	"io"
	"net/smtp"
	"os"

	// "log"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
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
var log *logrus.Logger

type ResponseData struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// QueryParams struct to handle filtering, sorting, and pagination parameters
type QueryParams struct {
	SearchTerm   string `json:"search_term"`
	SortField    string `json:"sort_field"`
	SortDir      string `json:"sort_dir"`
	Page         int    `json:"page"`
	ItemsPerPage int    `json:"items_per_page"`
}

// PaginatedResponse struct to return paginated data
type PaginatedResponse struct {
	Status      string      `json:"status"`
	Message     string      `json:"message"`
	Data        interface{} `json:"data"`
	TotalItems  int64       `json:"total_items"`
	TotalPages  int         `json:"total_pages"`
	CurrentPage int         `json:"current_page"`
}

// Add new types for filter handling
type FilterParams struct {
	Field    string `json:"field"`
	Value    string `json:"value"`
	Operator string `json:"operator"`
}

// Custom error types
var (
	ErrUserNotFound      = errors.New("user not found")
	ErrInvalidInput      = errors.New("invalid input")
	ErrDuplicateEmail    = errors.New("email already exists")
	ErrDatabaseOperation = errors.New("database operation failed")
)

// Initialize database connection
// func initDB() {
// 	var err error
// 	// Update credentials according to your PostgreSQL setup
// 	dsn := "host=localhost user=abukhassymkhydyrbayev password=admin dbname=social_pub port=5432 sslmode=disable"
// 	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
// 	if err != nil {
// 		log.Fatalf("Could not connect to the database: %v", err)
// 	}
// 	fmt.Println("Connected to the database")

// 	// AutoMigrate to ensure the users table exists with the correct schema
// 	err = db.AutoMigrate(&User{})
// 	if err != nil {
// 		log.Fatalf("Could not migrate database: %v", err)
// 	}

// 	// Initialize logger
// 	log = logrus.New()
// 	log.SetFormatter(&logrus.JSONFormatter{})
// 	log.SetLevel(logrus.InfoLevel)
// 	log.Info("Logger initialized")
// }

func initDB() {
	var err error
	dsn := "host=localhost user=abukhassymkhydyrbayev password=admin dbname=social_pub port=5432 sslmode=disable"

	log = logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetLevel(logrus.InfoLevel)

	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.WithError(err).Fatal("Failed to connect to database")
	}
	log.Info("Successfully connected to database")

	err = db.AutoMigrate(&User{})
	if err != nil {
		log.WithError(err).Fatal("Database migration failed")
	}
	log.Info("Database migration completed successfully")
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
// func createUser(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")

// 	var user User
// 	err := json.NewDecoder(r.Body).Decode(&user)
// 	if err != nil {
// 		// Ensure JSON error response
// 		w.WriteHeader(http.StatusBadRequest)
// 		json.NewEncoder(w).Encode(ResponseData{
// 			Status:  "error",
// 			Message: "Invalid request body",
// 		})
// 		return
// 	}

// 	// Validate input
// 	if user.UserName == "" || user.UserEmail == "" {
// 		w.WriteHeader(http.StatusBadRequest)
// 		json.NewEncoder(w).Encode(ResponseData{
// 			Status:  "error",
// 			Message: "Name and email are required",
// 		})
// 		return
// 	}

// 	// Validate email
// 	if !isValidEmail(user.UserEmail) {
// 		http.Error(w, "Invalid email format", http.StatusBadRequest)
// 		return
// 	}

// 	// Set timestamps
// 	now := time.Now()
// 	user.CreatedAt = now
// 	user.UpdatedAt = now

// 	// Create user in database
// 	result := db.Create(&user)
// 	if result.Error != nil {
// 		w.WriteHeader(http.StatusInternalServerError)
// 		json.NewEncoder(w).Encode(ResponseData{
// 			Status:  "error",
// 			Message: fmt.Sprintf("Could not create user: %v", result.Error),
// 		})
// 		return
// 	}

// 	// Respond with created user
// 	w.WriteHeader(http.StatusCreated)
// 	json.NewEncoder(w).Encode(ResponseData{
// 		Status:  "success",
// 		Message: "User created successfully",
// 		Data:    user,
// 	})
// }

// func createUser(w http.ResponseWriter, r *http.Request) {
// 	logger := log.WithField("handler", "createUser")

// 	var user User
// 	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
// 		logger.WithError(err).Error("Failed to decode request body")
// 		w.WriteHeader(http.StatusBadRequest)
// 		json.NewEncoder(w).Encode(ResponseData{
// 			Status:  "error",
// 			Message: "Invalid request body",
// 		})
// 		return
// 	}

// 	if user.UserName == "" || user.UserEmail == "" {
// 		logger.Warn("Missing required fields")
// 		w.WriteHeader(http.StatusBadRequest)
// 		json.NewEncoder(w).Encode(ResponseData{
// 			Status:  "error",
// 			Message: "Name and email are required",
// 		})
// 		return
// 	}

// 	if !isValidEmail(user.UserEmail) {
// 		logger.WithField("email", user.UserEmail).Warn("Invalid email format")
// 		http.Error(w, "Invalid email format", http.StatusBadRequest)
// 		return
// 	}

// 	now := time.Now()
// 	user.CreatedAt = now
// 	user.UpdatedAt = now

// 	result := db.Create(&user)
// 	if result.Error != nil {
// 		logger.WithError(result.Error).Error("Failed to create user in database")
// 		w.WriteHeader(http.StatusInternalServerError)
// 		json.NewEncoder(w).Encode(ResponseData{
// 			Status:  "error",
// 			Message: "Could not create user",
// 		})
// 		return
// 	}

// 	logger.WithField("user_id", user.UserID).Info("User created successfully")
// 	w.WriteHeader(http.StatusCreated)
// 	json.NewEncoder(w).Encode(ResponseData{
// 		Status:  "success",
// 		Message: "User created successfully",
// 		Data:    user,
// 	})
// }

func createUser(w http.ResponseWriter, r *http.Request) {
	logger := log.WithField("handler", "createUser")

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		handleError(w, fmt.Errorf("%w: %v", ErrInvalidInput, err), http.StatusBadRequest, logger)
		return
	}

	if err := validateUser(user); err != nil {
		handleError(w, err, http.StatusBadRequest, logger)
		return
	}

	if err := db.Create(&user).Error; err != nil {
		if isDuplicateEmailError(err) {
			handleError(w, ErrDuplicateEmail, http.StatusConflict, logger)
			return
		}
		handleError(w, fmt.Errorf("%w: %v", ErrDatabaseOperation, err), http.StatusInternalServerError, logger)
		return
	}

	sendJSONResponse(w, http.StatusCreated, ResponseData{
		Status:  "success",
		Message: "User created successfully",
		Data:    user,
	})
}

// Get All Users
func getAllUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse query parameters
	filterField := r.URL.Query().Get("filter_field")
	filterValue := r.URL.Query().Get("filter_value")
	filterOperator := r.URL.Query().Get("filter_operator")
	sortField := r.URL.Query().Get("sort_field")
	sortDir := r.URL.Query().Get("sort_dir")

	// Parse pagination parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	itemsPerPage := 5 // Default items per page

	// Build base query
	query := db.Model(&User{})

	// Apply filters if provided
	if filterValue != "" {
		query = applyFilter(query, filterField, filterValue, filterOperator)
	}

	// Get total count before pagination
	var totalItems int64
	query.Count(&totalItems)

	// Apply sorting
	query = applySorting(query, sortField, sortDir)

	// Apply pagination
	offset := (page - 1) * itemsPerPage
	query = query.Offset(offset).Limit(itemsPerPage)

	// Execute query
	var users []User
	result := query.Find(&users)
	if result.Error != nil {
		sendErrorResponse(w, "Could not retrieve users", http.StatusInternalServerError)
		return
	}

	// Calculate total pages
	totalPages := int(math.Ceil(float64(totalItems) / float64(itemsPerPage)))

	// Send response
	json.NewEncoder(w).Encode(PaginatedResponse{
		Status:      "success",
		Message:     "Users retrieved successfully",
		Data:        users,
		TotalItems:  totalItems,
		TotalPages:  totalPages,
		CurrentPage: page,
	})
}

// Helper function to apply filters
func applyFilter(query *gorm.DB, field, value, operator string) *gorm.DB {
	switch field {
	case "name":
		return applyStringFilter(query, "user_name", value, operator)
	case "email":
		return applyStringFilter(query, "user_email", value, operator)
	case "date":
		return applyDateFilter(query, "created_at", value, operator)
	default:
		return query
	}
}

// Helper function for string filters
func applyStringFilter(query *gorm.DB, field, value, operator string) *gorm.DB {
	switch operator {
	case "contains":
		return query.Where(field+" ILIKE ?", "%"+value+"%")
	case "equals":
		return query.Where(field+" = ?", value)
	case "startsWith":
		return query.Where(field+" ILIKE ?", value+"%")
	case "endsWith":
		return query.Where(field+" ILIKE ?", "%"+value)
	default:
		return query
	}
}

// Helper function for sorting
func applySorting(query *gorm.DB, field, direction string) *gorm.DB {
	if field == "" {
		return query.Order("user_id asc")
	}

	if direction != "desc" {
		direction = "asc"
	}

	return query.Order(fmt.Sprintf("%s %s", field, direction))
}

// Helper function for error responses
func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ResponseData{
		Status:  "error",
		Message: message,
	})
}

// Centralized error handler
func handleError(w http.ResponseWriter, err error, statusCode int, logger *logrus.Entry) {
	logger.WithError(err).Error("Operation failed")

	var response ResponseData
	switch {
	case errors.Is(err, ErrUserNotFound):
		response = ResponseData{Status: "error", Message: "User not found"}
	case errors.Is(err, ErrInvalidInput):
		response = ResponseData{Status: "error", Message: "Invalid input provided"}
	case errors.Is(err, ErrDuplicateEmail):
		response = ResponseData{Status: "error", Message: "Email already exists"}
	default:
		response = ResponseData{Status: "error", Message: "Internal server error"}
	}

	sendJSONResponse(w, statusCode, response)
}

// Helper function for JSON responses
func sendJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.WithError(err).Error("Failed to encode JSON response")
	}
}

// User validation
func validateUser(user User) error {
	if user.UserName == "" {
		return fmt.Errorf("%w: username is required", ErrInvalidInput)
	}
	if user.UserEmail == "" {
		return fmt.Errorf("%w: email is required", ErrInvalidInput)
	}
	if !isValidEmail(user.UserEmail) {
		return fmt.Errorf("%w: invalid email format", ErrInvalidInput)
	}
	return nil
}

// Helper to check for duplicate email errors
func isDuplicateEmailError(err error) bool {
	return strings.Contains(err.Error(), "duplicate key value violates unique constraint")
}

// Helper function for date filters
func applyDateFilter(query *gorm.DB, field, value, operator string) *gorm.DB {
	switch operator {
	case "equals":
		return query.Where(field+" BETWEEN ? AND ?", value, value+"T23:59:59Z")
	case "before":
		return query.Where(field+" < ?", value)
	case "after":
		return query.Where(field+" > ?", value)
	default:
		return query
	}
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
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, x-ijt, X-Requested-With, Authorization")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	// Handle preflight requests
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract ID from query
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Missing 'id' parameter", http.StatusBadRequest)
		return
	}

	// Convert string ID to uint
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid ID format", http.StatusBadRequest)
		return
	}

	var user User
	result := db.First(&user, uint(id))
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ResponseData{
				Status:  "error",
				Message: "User not found",
			})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ResponseData{
				Status:  "error",
				Message: fmt.Sprintf("Error retrieving user: %v", result.Error),
			})
		}
		return
	}

	// Return successful response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ResponseData{
		Status:  "success",
		Message: "User retrieved successfully",
		Data:    user,
	})
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

func sendEmail(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Unable to process form", http.StatusBadRequest)
		return
	}

	// Extract form fields
	from := r.FormValue("email")
	message := r.FormValue("message")

	// Create a new email
	e := email.NewEmail()
	e.From = from
	e.To = []string{"kh.abukhassym@gmail.com"}
	e.Subject = "Support Request"
	e.Text = []byte(message)

	// Handle attachment
	file, header, err := r.FormFile("attachment")
	if err == nil {
		defer file.Close()
		attachmentPath := "./" + header.Filename
		out, err := os.Create(attachmentPath)
		if err != nil {
			log.Println("Error saving attachment:", err)
			http.Error(w, "Error saving attachment", http.StatusInternalServerError)
			return
		}
		defer out.Close()

		// Write file content
		if _, err = io.Copy(out, file); err != nil {
			log.Println("Error copying file:", err)
			http.Error(w, "Error processing file", http.StatusInternalServerError)
			return
		}

		// Attach file to email
		e.AttachFile(attachmentPath)
		defer os.Remove(attachmentPath)
	}

	// Send email via SMTP
	auth := smtp.PlainAuth("", "kh.abukhassym@gmail.com", "bsml lwzy akas ezfm", "smtp.gmail.com")
	if err := e.Send("smtp.gmail.com:587", auth); err != nil {
		log.Println("Error sending email:", err)
		http.Error(w, "Error sending email", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}

var limiter = rate.NewLimiter(1, 3) // 1 request per second, burst of 3 requests

func main() {
	// Initialize the database
	initDB()

	// Routes
	http.HandleFunc("/post", rateLimitedHandler(postHandler))
	http.HandleFunc("/get", rateLimitedHandler(getHandler))

	// Wrap your handlers with both CORS middleware and rate limiting
	http.HandleFunc("/users", rateLimitedHandler(corsMiddleware(userHandler)))
	http.HandleFunc("/user/create", rateLimitedHandler(corsMiddleware(createUserHandler)))
	http.HandleFunc("/user/update", rateLimitedHandler(corsMiddleware(updateUserHandler)))
	http.HandleFunc("/user/delete", rateLimitedHandler(corsMiddleware(deleteUserHandler)))
	http.HandleFunc("/user/get", rateLimitedHandler(corsMiddleware(getUserHandler)))

	// Send Email
	http.HandleFunc("/send-email", corsMiddleware(sendEmail))

	// Serve static files
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	// Start the server
	fmt.Println("Server is running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// rateLimitedHandler wraps an HTTP handler with rate limiting
func rateLimitedHandler(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Wait for the limiter to allow the request
		if err := limiter.Wait(context.Background()); err != nil {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		// Call the original handler
		h(w, r)
	}
}
