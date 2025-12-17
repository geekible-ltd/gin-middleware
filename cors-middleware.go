package ginmiddleware

import (
	"net/http"
	"strings"

	corsmodels "github.com/geekible-ltd/gin-middleware/cors-models"
	"github.com/gin-gonic/gin"
)

func CORSMiddleware(cfg *corsmodels.CORSConfigDTO) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Set CORS headers
		origin := c.GetHeader("Origin")

		// Check if origin is allowed
		if isOriginAllowed(origin, cfg.AllowedOrigins) {
			c.Header("Access-Control-Allow-Origin", origin)
		} else if contains(cfg.AllowedOrigins, "*") {
			c.Header("Access-Control-Allow-Origin", "*")
		}

		// Set other CORS headers
		c.Header("Access-Control-Allow-Methods", strings.Join(cfg.AllowedMethods, ","))

		if contains(cfg.AllowedHeaders, "*") {
			c.Header("Access-Control-Allow-Headers", "*")
		} else {
			c.Header("Access-Control-Allow-Headers", strings.Join(cfg.AllowedHeaders, ","))
		}

		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400") // 24 hours

		// Handle preflight OPTIONS requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// isOriginAllowed checks if the origin is in the allowed list
func isOriginAllowed(origin string, allowedOrigins []string) bool {
	for _, allowed := range allowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
		// Handle wildcard domains like *.example.com
		if strings.HasPrefix(allowed, "*.") {
			domain := strings.TrimPrefix(allowed, "*.")
			if strings.HasSuffix(origin, domain) {
				return true
			}
		}
	}
	return false
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
