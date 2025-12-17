package ginmiddleware

import (
	"net/http"
	"strings"

	"github.com/geekible-ltd/gin-middleware/utils"
	"github.com/gin-gonic/gin"
)

const (
	TokenKey = "token"
)

func BearerAuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		bearerToken := c.GetHeader("Authorization")
		if bearerToken == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
			return
		}

		token := strings.Split(bearerToken, " ")[1]
		tokenDto, err := utils.ParseJWT(token, []byte(jwtSecret))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		c.Set(TokenKey, tokenDto)

		c.Next()
	}
}
