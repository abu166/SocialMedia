package main

import (
	"encoding/json"
	"fmt"
	// "io"
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

const maxRequestBodySize = 1 << 20 // 1MB limit

func postHandler(w http.ResponseWriter, r *http.Request) {
	// Restrict to POST method
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		response := ResponseData{"fail", "Only POST method is allowed"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Set response content type to JSON
	w.Header().Set("Content-Type", "application/json")

	// Limit the request body size to prevent abuse
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	// Check if body is empty
	if r.ContentLength == 0 {
		w.WriteHeader(http.StatusBadRequest)
		response := ResponseData{"fail", "Request body cannot be empty"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Read and parse the JSON body
	var requestData RequestData
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&requestData)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		response := ResponseData{"fail", "Invalid JSON message or request too large"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Validate "message" field
	if requestData.Message == "" {
		w.WriteHeader(http.StatusBadRequest)
		response := ResponseData{"fail", "Message field is required"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Print the received message to the server console
	fmt.Printf("Received message: %s\n", requestData.Message)

	// Return success response
	response := ResponseData{"success", "Data successfully received"}
	json.NewEncoder(w).Encode(response)
}


const maxQueryParamSize = 1024 // Limit query string size to 1KB

// Handler for GET requests
func getHandler(w http.ResponseWriter, r *http.Request) {
	// Restrict to GET method
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set response content type to JSON
	w.Header().Set("Content-Type", "application/json")

	// Check the total size of query parameters
	queryString := r.URL.RawQuery
	if len(queryString) > maxQueryParamSize {
		http.Error(w, "Query string size exceeds limit", http.StatusRequestEntityTooLarge)
		return
	}

	// Log query parameters (if any)
	queryParams := r.URL.Query()
	if len(queryParams) == 0 {
		fmt.Println("No query parameters provided")
	} else {
		fmt.Println("Query Parameters:", queryParams)
	}

	// Validate specific query parameter (optional)
	if msg := queryParams.Get("message"); msg == "" {
		w.WriteHeader(http.StatusBadRequest)
		response := ResponseData{"fail", "Missing 'message' query parameter"}
		json.NewEncoder(w).Encode(response)
		return
	} else {
		// Check if 'message' parameter exceeds max length
		if len(msg) > 256 { // You can adjust this length
			w.WriteHeader(http.StatusBadRequest)
			response := ResponseData{"fail", "'message' parameter is too long"}
			json.NewEncoder(w).Encode(response)
			return
		}
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
