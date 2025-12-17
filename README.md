# Gin Middleware Package

A comprehensive collection of middleware for Gin web framework, providing authentication, CORS handling, and rate limiting functionality.

[![Go Version](https://img.shields.io/badge/Go-1.24.5-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Features

- 🔐 **Bearer Token Authentication** - JWT-based authentication middleware
- 🌐 **CORS Middleware** - Flexible Cross-Origin Resource Sharing configuration
- ⏱️ **Rate Limiting** - IP-based rate limiting to prevent abuse
- 🛠️ **JWT Utilities** - Helper functions for JWT generation, parsing, and validation

## Installation

```bash
go get github.com/geekible-ltd/gin-middleware
```

## Table of Contents

- [Bearer Authentication Middleware](#bearer-authentication-middleware)
- [CORS Middleware](#cors-middleware)
- [Rate Limit Middleware](#rate-limit-middleware)
- [JWT Utilities](#jwt-utilities)
- [Complete Examples](#complete-examples)
- [API Reference](#api-reference)

---

## Bearer Authentication Middleware

The `BearerAuthMiddleware` validates JWT tokens from the `Authorization` header and makes the token data available in the Gin context.

### Basic Usage

```go
package main

import (
    "github.com/gin-gonic/gin"
    ginmiddleware "github.com/geekible-ltd/gin-middleware"
    authmodels "github.com/geekible-ltd/gin-middleware/auth-models"
)

func main() {
    router := gin.Default()
    
    // Your JWT secret key
    jwtSecret := "your-super-secret-key"
    
    // Protected routes
    protected := router.Group("/api")
    protected.Use(ginmiddleware.BearerAuthMiddleware(jwtSecret))
    {
        protected.GET("/profile", getProfile)
        protected.POST("/data", createData)
    }
    
    router.Run(":8080")
}

func getProfile(c *gin.Context) {
    // Retrieve token data from context
    tokenData, exists := c.Get(ginmiddleware.TokenKey)
    if !exists {
        c.JSON(500, gin.H{"error": "Token not found"})
        return
    }
    
    token := tokenData.(authmodels.TokenDTO)
    c.JSON(200, gin.H{
        "user_id":    token.Sub,
        "email":      token.Email,
        "first_name": token.FirstName,
        "last_name":  token.LastName,
        "role":       token.Role,
    })
}
```

### Making Authenticated Requests

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8080/api/profile
```

### Expected Responses

**Success (200 OK):**
```json
{
  "user_id": "123",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "role": "admin"
}
```

**Missing Token (401 Unauthorized):**
```json
{
  "error": "Missing Authorization header"
}
```

**Invalid Token (401 Unauthorized):**
```json
{
  "error": "Invalid token"
}
```

---

## CORS Middleware

The `CORSMiddleware` handles Cross-Origin Resource Sharing (CORS) with flexible configuration for origins, methods, and headers.

### Basic Usage

```go
package main

import (
    "github.com/gin-gonic/gin"
    ginmiddleware "github.com/geekible-ltd/gin-middleware"
    corsmodels "github.com/geekible-ltd/gin-middleware/cors-models"
)

func main() {
    router := gin.Default()
    
    // Configure CORS
    corsConfig := &corsmodels.CORSConfigDTO{
        AllowedOrigins: []string{"http://localhost:3000", "https://myapp.com"},
        AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
        AllowedHeaders: []string{"Content-Type", "Authorization"},
    }
    
    // Apply CORS middleware globally
    router.Use(ginmiddleware.CORSMiddleware(corsConfig))
    
    router.GET("/api/data", getData)
    router.POST("/api/data", createData)
    
    router.Run(":8080")
}
```

### Configuration Options

#### Allow All Origins

```go
corsConfig := &corsmodels.CORSConfigDTO{
    AllowedOrigins: []string{"*"},
    AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
    AllowedHeaders: []string{"*"},
}
```

#### Wildcard Subdomains

```go
corsConfig := &corsmodels.CORSConfigDTO{
    AllowedOrigins: []string{"*.example.com"},  // Allows all subdomains
    AllowedMethods: []string{"GET", "POST"},
    AllowedHeaders: []string{"Content-Type", "Authorization"},
}
```

#### Specific Origins

```go
corsConfig := &corsmodels.CORSConfigDTO{
    AllowedOrigins: []string{
        "http://localhost:3000",
        "https://app.example.com",
        "https://api.example.com",
    },
    AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
    AllowedHeaders: []string{
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "Accept",
    },
}
```

### CORS Headers Set

The middleware automatically sets the following headers:
- `Access-Control-Allow-Origin`
- `Access-Control-Allow-Methods`
- `Access-Control-Allow-Headers`
- `Access-Control-Allow-Credentials: true`
- `Access-Control-Max-Age: 86400` (24 hours)

---

## Rate Limit Middleware

The `RateLimitMiddleware` implements IP-based rate limiting using the token bucket algorithm.

### Basic Usage

```go
package main

import (
    "github.com/gin-gonic/gin"
    ginmiddleware "github.com/geekible-ltd/gin-middleware"
)

func main() {
    router := gin.Default()
    
    // Rate limit: 10 requests per second with burst of 5
    router.Use(ginmiddleware.RateLimitMiddleware(10, 5))
    
    router.GET("/api/data", getData)
    
    router.Run(":8080")
}
```

### Parameters

- **requestPerSecond** (int): Number of requests allowed per second
- **burst** (int): Maximum burst size for traffic spikes

### Examples

#### Strict Rate Limiting
```go
// Allow 5 requests per second, no burst
router.Use(ginmiddleware.RateLimitMiddleware(5, 1))
```

#### Moderate Rate Limiting
```go
// Allow 20 requests per second with burst of 10
router.Use(ginmiddleware.RateLimitMiddleware(20, 10))
```

#### Generous Rate Limiting
```go
// Allow 100 requests per second with burst of 50
router.Use(ginmiddleware.RateLimitMiddleware(100, 50))
```

### Rate Limit Response

When rate limit is exceeded (429 Too Many Requests):
```json
{
  "error": "Rate limit exceeded"
}
```

### Per-Route Rate Limiting

```go
// Different rate limits for different routes
publicAPI := router.Group("/public")
publicAPI.Use(ginmiddleware.RateLimitMiddleware(5, 2))
{
    publicAPI.GET("/data", getData)
}

authenticatedAPI := router.Group("/api")
authenticatedAPI.Use(ginmiddleware.BearerAuthMiddleware(jwtSecret))
authenticatedAPI.Use(ginmiddleware.RateLimitMiddleware(50, 20))
{
    authenticatedAPI.GET("/data", getAuthData)
}
```

---

## JWT Utilities

The package includes utility functions for JWT token management.

### Generate JWT Token

```go
package main

import (
    "fmt"
    "github.com/geekible-ltd/gin-middleware/utils"
)

func main() {
    jwtSecret := []byte("your-super-secret-key")
    
    token, err := utils.GenerateJWT(
        "user123",              // userID
        "company456",           // companyID
        "user@example.com",     // email
        "John",                 // firstName
        "Doe",                  // lastName
        "admin",                // role
        jwtSecret,
    )
    
    if err != nil {
        fmt.Println("Error generating token:", err)
        return
    }
    
    fmt.Println("Generated Token:", token)
}
```

**Note:** Tokens expire after 10 hours by default.

### Parse JWT Token

```go
package main

import (
    "fmt"
    "github.com/geekible-ltd/gin-middleware/utils"
)

func main() {
    jwtSecret := []byte("your-super-secret-key")
    tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    
    tokenDTO, err := utils.ParseJWT(tokenString, jwtSecret)
    if err != nil {
        fmt.Println("Error parsing token:", err)
        return
    }
    
    fmt.Printf("User ID: %v\n", tokenDTO.Sub)
    fmt.Printf("Email: %s\n", tokenDTO.Email)
    fmt.Printf("Role: %s\n", tokenDTO.Role)
}
```

### Validate User Role

```go
package main

import (
    "fmt"
    "github.com/geekible-ltd/gin-middleware/utils"
)

func main() {
    jwtSecret := []byte("your-super-secret-key")
    tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    
    isValid, err := utils.ValidateUserRole(
        "user123",      // userID
        "admin",        // required role
        tokenString,    // JWT token
        jwtSecret,
    )
    
    if err != nil {
        fmt.Println("Error validating role:", err)
        return
    }
    
    if isValid {
        fmt.Println("User has the required role")
    } else {
        fmt.Println("User does not have the required role")
    }
}
```

---

## Complete Examples

### Full Application with All Middleware

```go
package main

import (
    "net/http"
    "os"

    "github.com/gin-gonic/gin"
    ginmiddleware "github.com/geekible-ltd/gin-middleware"
    authmodels "github.com/geekible-ltd/gin-middleware/auth-models"
    corsmodels "github.com/geekible-ltd/gin-middleware/cors-models"
    "github.com/geekible-ltd/gin-middleware/utils"
)

func main() {
    router := gin.Default()
    
    // Get JWT secret from environment
    jwtSecret := os.Getenv("JWT_SECRET")
    if jwtSecret == "" {
        jwtSecret = "default-secret-key-change-in-production"
    }
    
    // Configure CORS
    corsConfig := &corsmodels.CORSConfigDTO{
        AllowedOrigins: []string{"http://localhost:3000", "https://myapp.com"},
        AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
        AllowedHeaders: []string{"Content-Type", "Authorization"},
    }
    
    // Apply global middleware
    router.Use(ginmiddleware.CORSMiddleware(corsConfig))
    router.Use(ginmiddleware.RateLimitMiddleware(20, 10))
    
    // Public routes
    router.POST("/auth/login", login(jwtSecret))
    router.GET("/public/health", healthCheck)
    
    // Protected routes with authentication
    api := router.Group("/api")
    api.Use(ginmiddleware.BearerAuthMiddleware(jwtSecret))
    {
        api.GET("/profile", getProfile)
        api.PUT("/profile", updateProfile)
        
        // Admin-only routes with stricter rate limiting
        admin := api.Group("/admin")
        admin.Use(ginmiddleware.RateLimitMiddleware(5, 2))
        {
            admin.GET("/users", getAllUsers)
            admin.DELETE("/users/:id", deleteUser)
        }
    }
    
    router.Run(":8080")
}

// Login handler - generates JWT token
func login(jwtSecret string) gin.HandlerFunc {
    return func(c *gin.Context) {
        var credentials struct {
            Email    string `json:"email" binding:"required"`
            Password string `json:"password" binding:"required"`
        }
        
        if err := c.ShouldBindJSON(&credentials); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }
        
        // TODO: Validate credentials against database
        // This is a simplified example
        if credentials.Email == "user@example.com" && credentials.Password == "password" {
            token, err := utils.GenerateJWT(
                "user123",
                "company456",
                credentials.Email,
                "John",
                "Doe",
                "admin",
                []byte(jwtSecret),
            )
            
            if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
                return
            }
            
            c.JSON(http.StatusOK, gin.H{
                "token": token,
                "type":  "Bearer",
            })
            return
        }
        
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
    }
}

func healthCheck(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"status": "healthy"})
}

func getProfile(c *gin.Context) {
    tokenData, exists := c.Get(ginmiddleware.TokenKey)
    if !exists {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Token not found"})
        return
    }
    
    token := tokenData.(authmodels.TokenDTO)
    c.JSON(http.StatusOK, gin.H{
        "user": gin.H{
            "id":         token.Sub,
            "company_id": token.CompanyID,
            "email":      token.Email,
            "first_name": token.FirstName,
            "last_name":  token.LastName,
            "role":       token.Role,
        },
    })
}

func updateProfile(c *gin.Context) {
    tokenData, _ := c.Get(ginmiddleware.TokenKey)
    token := tokenData.(authmodels.TokenDTO)
    
    var updateData struct {
        FirstName string `json:"first_name"`
        LastName  string `json:"last_name"`
    }
    
    if err := c.ShouldBindJSON(&updateData); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    // TODO: Update database
    c.JSON(http.StatusOK, gin.H{
        "message": "Profile updated",
        "user_id": token.Sub,
    })
}

func getAllUsers(c *gin.Context) {
    // Check if user has admin role
    tokenData, _ := c.Get(ginmiddleware.TokenKey)
    token := tokenData.(authmodels.TokenDTO)
    
    if token.Role != "admin" {
        c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
        return
    }
    
    // TODO: Fetch users from database
    c.JSON(http.StatusOK, gin.H{
        "users": []gin.H{
            {"id": "1", "email": "user1@example.com"},
            {"id": "2", "email": "user2@example.com"},
        },
    })
}

func deleteUser(c *gin.Context) {
    userID := c.Param("id")
    
    // Check if user has admin role
    tokenData, _ := c.Get(ginmiddleware.TokenKey)
    token := tokenData.(authmodels.TokenDTO)
    
    if token.Role != "admin" {
        c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
        return
    }
    
    // TODO: Delete user from database
    c.JSON(http.StatusOK, gin.H{
        "message": "User deleted",
        "user_id": userID,
    })
}
```

### Testing Your API

#### 1. Health Check (Public)
```bash
curl http://localhost:8080/public/health
```

#### 2. Login
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password"
  }'
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "type": "Bearer"
}
```

#### 3. Access Protected Route
```bash
export TOKEN="your-jwt-token-here"

curl http://localhost:8080/api/profile \
  -H "Authorization: Bearer $TOKEN"
```

#### 4. Update Profile
```bash
curl -X PUT http://localhost:8080/api/profile \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "Jane",
    "last_name": "Smith"
  }'
```

#### 5. Admin Endpoint
```bash
curl http://localhost:8080/api/admin/users \
  -H "Authorization: Bearer $TOKEN"
```

---

## API Reference

### Middleware Functions

#### `BearerAuthMiddleware(jwtSecret string) gin.HandlerFunc`

Validates JWT tokens from the Authorization header.

**Parameters:**
- `jwtSecret` (string): Secret key for JWT validation

**Context Values Set:**
- `ginmiddleware.TokenKey`: Contains `authmodels.TokenDTO` with user information

**Errors:**
- 401: Missing Authorization header
- 401: Invalid token

---

#### `CORSMiddleware(cfg *corsmodels.CORSConfigDTO) gin.HandlerFunc`

Handles CORS with configurable origins, methods, and headers.

**Parameters:**
- `cfg` (*corsmodels.CORSConfigDTO): CORS configuration

**Configuration Fields:**
- `AllowedOrigins` ([]string): List of allowed origins (supports wildcards)
- `AllowedMethods` ([]string): List of allowed HTTP methods
- `AllowedHeaders` ([]string): List of allowed headers

---

#### `RateLimitMiddleware(requestPerSecond, burst int) gin.HandlerFunc`

Implements IP-based rate limiting.

**Parameters:**
- `requestPerSecond` (int): Maximum requests per second
- `burst` (int): Burst capacity for traffic spikes

**Errors:**
- 429: Rate limit exceeded

---

### Utility Functions

#### `utils.GenerateJWT(...) (string, error)`

Generates a JWT token with user information.

**Parameters:**
- `userID` (any): User identifier
- `companyID` (any): Company identifier
- `email` (string): User email
- `firstName` (string): User first name
- `lastName` (string): User last name
- `role` (string): User role
- `jwtSecret` ([]byte): Secret key for signing

**Returns:**
- Token string
- Error (if any)

---

#### `utils.ParseJWT(tokenString string, jwtSecret []byte) (authmodels.TokenDTO, error)`

Parses and validates a JWT token.

**Parameters:**
- `tokenString` (string): JWT token to parse
- `jwtSecret` ([]byte): Secret key for validation

**Returns:**
- TokenDTO with user information
- Error (if any)

---

#### `utils.ValidateUserRole(userId any, requiredRole, token string, jwtSecret []byte) (bool, error)`

Validates if a user has the required role.

**Parameters:**
- `userId` (any): User identifier
- `requiredRole` (string): Required role
- `token` (string): JWT token
- `jwtSecret` ([]byte): Secret key

**Returns:**
- Boolean indicating if user has the role
- Error (if any)

---

### Models

#### `authmodels.TokenDTO`

```go
type TokenDTO struct {
    Sub       any    `json:"sub"`        // User ID
    CompanyID any    `json:"company_id"` // Company ID
    Email     string `json:"email"`      // User email
    FirstName string `json:"first_name"` // First name
    LastName  string `json:"last_name"`  // Last name
    Role      string `json:"role"`       // User role
    Exp       int64  `json:"exp"`        // Expiration time
    Iat       int64  `json:"iat"`        // Issued at time
}
```

#### `corsmodels.CORSConfigDTO`

```go
type CORSConfigDTO struct {
    AllowedOrigins []string `json:"allowed_origins"` // Allowed origins
    AllowedMethods []string `json:"allowed_methods"` // Allowed methods
    AllowedHeaders []string `json:"allowed_headers"` // Allowed headers
}
```

---

## Best Practices

### Security

1. **Never hardcode JWT secrets** - Use environment variables
   ```go
   jwtSecret := os.Getenv("JWT_SECRET")
   ```

2. **Use strong JWT secrets** - Minimum 32 characters, random
   ```bash
   export JWT_SECRET=$(openssl rand -base64 32)
   ```

3. **Enable HTTPS in production** - Never send tokens over HTTP

4. **Implement token refresh** - Tokens expire after 10 hours

5. **Validate user permissions** - Don't rely on JWT alone for authorization

### Rate Limiting

1. **Adjust limits based on route** - More restrictive for public endpoints
2. **Consider using Redis** - For distributed rate limiting across multiple servers
3. **Monitor rate limit hits** - Track when users hit limits
4. **Provide feedback** - Include rate limit headers in responses

### CORS

1. **Be specific with origins** - Avoid `*` in production
2. **Limit allowed methods** - Only enable methods you use
3. **Restrict headers** - Only allow necessary headers
4. **Test from browser** - CORS only affects browser requests

---

## Environment Variables

```bash
# Required
export JWT_SECRET="your-super-secret-key-at-least-32-characters"

# Optional
export PORT="8080"
export GIN_MODE="release"  # production mode
```

---

## Dependencies

- [Gin Web Framework](https://github.com/gin-gonic/gin) v1.11.0
- [golang-jwt/jwt](https://github.com/golang-jwt/jwt) v5.3.0
- [golang.org/x/time/rate](https://pkg.go.dev/golang.org/x/time/rate) v0.14.0

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Support

For issues, questions, or contributions, please open an issue on GitHub.

---

## Changelog

### v1.0.0
- Initial release
- Bearer token authentication
- CORS middleware
- Rate limiting middleware
- JWT utilities

---

Made with ❤️ by Geekible Ltd

