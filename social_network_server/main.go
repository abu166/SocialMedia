package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

// Define structs for data
type RequestData struct {
	Message string `json:"message"`
}

type ResponseData struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

const (
	maxRequestBodySize = 1 << 20 // Limit request size to 1MB
)

// Handler for POST requests
func postHandler(w http.ResponseWriter, r *http.Request) {
	// Restrict to POST method
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Ensure the Content-Type is application/json
	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		response := ResponseData{"fail", "Content-Type must be application/json"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Set a limit for request body size to prevent abuse
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	defer r.Body.Close()

	// Set response content type to JSON
	w.Header().Set("Content-Type", "application/json")

	// Read and parse JSON body
	var requestData RequestData
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		response := ResponseData{"fail", "Error reading request body"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Decode the JSON content
	if err := json.Unmarshal(body, &requestData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		response := ResponseData{"fail", "Invalid JSON format"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Validate the "message" field
	if requestData.Message == "" {
		w.WriteHeader(http.StatusBadRequest)
		response := ResponseData{"fail", "Message field is required"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Print the received message to the server console
	fmt.Printf("Received message: %s\n", requestData.Message)

	// Return success response
	w.WriteHeader(http.StatusOK)
	response := ResponseData{"success", "Data successfully received"}
	json.NewEncoder(w).Encode(response)
}

// Handler for GET requests
func getHandler(w http.ResponseWriter, r *http.Request) {
	// Restrict to GET method
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set response content type to JSON
	w.Header().Set("Content-Type", "application/json")

	// Log query parameters (if any)
	queryParams := r.URL.Query()
	if len(queryParams) == 0 {
		fmt.Println("No query parameters provided")
	}

	// Validate specific query parameter (optional)
	if msg := queryParams.Get("message"); msg == "" {
		w.WriteHeader(http.StatusBadRequest)
		response := ResponseData{"fail", "Missing 'message' query parameter"}
		json.NewEncoder(w).Encode(response)
		return
	} else {
		fmt.Println("Query parameter 'message':", msg)
	}

	// Return success response
	response := ResponseData{"success", "GET request received"}
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Println("Error encoding JSON response:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func main() {
	// Serve static files (HTML)
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	// Routes
	http.HandleFunc("/post", postHandler)
	http.HandleFunc("/get", getHandler)

	// Start the server on port 8080
	fmt.Println("Server is running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
