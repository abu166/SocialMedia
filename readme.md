# User Management System

A simple full-stack web application for managing users with CRUD operations. The system consists of a Go backend using GORM for database operations and a vanilla JavaScript frontend.

## Features

- Create new users with name and email
- Read/Display list of all users
- Update existing user information
- Delete users
- Input validation and error handling
- Responsive web interface
- CORS enabled for local development

## Prerequisites

- Go 1.x or later
- PostgreSQL
- Modern web browser
- Basic understanding of Go and JavaScript

## Technology Stack

- **Backend**: 
  - Go
  - GORM (PostgreSQL)
  - net/http package for server
- **Frontend**:
  - HTML
  - CSS
  - Vanilla JavaScript
  - Fetch API for HTTP requests

## Setup Instructions

### 1. Database Setup

1. Install PostgreSQL if you haven't already
2. Create a new database:
```sql
CREATE DATABASE social_pub;
```
3. Update the database connection string in `main.go`:
```go
dsn := "host=localhost user=your_username password=your_password dbname=social_pub port=5432 sslmode=disable"
```

### 2. Backend Setup

1. Clone the repository
2. Install Go dependencies:
```bash
go mod init your_module_name
go mod tidy
```
3. Install required packages:
```bash
go get -u gorm.io/gorm
go get -u gorm.io/driver/postgres
```

### 3. Frontend Setup

1. Place the `index.html` file in a `static` directory in your project root
2. Ensure the static file server is properly configured in `main.go`

## Running the Application

1. Start the Go server:
```bash
go run main.go
```
2. Open `index.html` in your web browser or serve it through the Go server at:
```
http://localhost:8080
```

## API Endpoints

- `GET /users` - Get all users
- `POST /users` - Create a new user
- `PUT /user/update` - Update an existing user
- `DELETE /user/delete` - Delete a user

## Project Structure

```
.
├── main.go          # Backend server and API handlers
├── static/          # Static files directory
│   └── index.html   # Frontend interface
└── README.md        # Project documentation
```

## Error Handling

The application includes comprehensive error handling for:
- Database connection issues
- Invalid input data
- Network errors
- CORS issues
- Server errors

## Security Features

- Input validation
- XSS prevention
- CORS configuration
- Request size limits
- Basic email validation

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check if PostgreSQL is running
   - Verify database credentials
   - Ensure database exists

2. **CORS Errors**
   - Check if the CORS middleware is properly configured
   - Verify the allowed origins in the CORS settings

3. **Frontend Not Loading**
   - Ensure the static files are in the correct directory
   - Check if the server is running on the correct port
   - Verify the file paths in your HTML

## Notes

- This is a development setup and should be properly configured for production use
- The frontend uses vanilla JavaScript for simplicity, but could be enhanced with a framework
- Additional security measures should be implemented for production deployment
