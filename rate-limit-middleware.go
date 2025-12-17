package ginmiddleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

var limiters = make(map[string]*rate.Limiter)

func RateLimitMiddleware(requestPerSecond, burst int) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if _, exists := limiters[ip]; !exists {
			limiters[ip] = rate.NewLimiter(rate.Limit(requestPerSecond), burst)
		}

		limiter := limiters[ip]
		if !limiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
			return
		}

		c.Next()
	}
}
