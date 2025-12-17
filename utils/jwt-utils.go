package utils

import (
	"errors"
	"fmt"
	"time"

	authmodels "github.com/geekible-ltd/gin-middleware/auth-models"
	"github.com/golang-jwt/jwt/v5"
)

func GenerateJWT(userID, companyID any, email, firstName, lastName, role string, jwtSecret []byte) (string, error) {
	claims := jwt.MapClaims{
		"sub":        userID,
		"company_id": companyID,
		"email":      email,
		"first_name": firstName,
		"last_name":  lastName,
		"role":       role,
		"exp":        time.Now().Add(10 * time.Hour).Unix(),
		"iat":        time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func ParseJWT(tokenString string, jwtSecret []byte) (authmodels.TokenDTO, error) {
	tok, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return jwtSecret, nil
	})
	if err != nil {
		return authmodels.TokenDTO{}, err
	}
	if !tok.Valid {
		return authmodels.TokenDTO{}, errors.New("invalid token")
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return authmodels.TokenDTO{}, errors.New("invalid claims")
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return authmodels.TokenDTO{}, errors.New("sub claim missing or invalid")
	}

	companyID, ok := claims["company_id"].(string)
	if !ok {
		return authmodels.TokenDTO{}, errors.New("company_id claim missing or invalid")
	}

	email, ok := claims["email"].(string)
	if !ok {
		return authmodels.TokenDTO{}, errors.New("email claim missing or invalid")
	}

	firstName, ok := claims["first_name"].(string)
	if !ok {
		return authmodels.TokenDTO{}, errors.New("first_name claim missing or invalid")
	}

	lastName, ok := claims["last_name"].(string)
	if !ok {
		return authmodels.TokenDTO{}, errors.New("last_name claim missing or invalid")
	}

	role, ok := claims["role"].(string)
	if !ok {
		return authmodels.TokenDTO{}, errors.New("role claim missing or invalid")
	}

	expFloat, ok := claims["exp"].(float64)
	if !ok {
		return authmodels.TokenDTO{}, errors.New("exp claim missing or invalid")
	}
	exp := int64(expFloat)

	iatFloat, ok := claims["iat"].(float64)
	if !ok {
		return authmodels.TokenDTO{}, errors.New("iat claim missing or invalid")
	}
	iat := int64(iatFloat)

	return authmodels.TokenDTO{
		Sub:       sub,
		CompanyID: companyID,
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		Role:      role,
		Exp:       exp,
		Iat:       iat,
	}, nil
}

func ValidateUserRole(userId any, requiredRole, token string, jwtSecret []byte) (bool, error) {
	tokenDTO, err := ParseJWT(token, jwtSecret)

	if err != nil {
		return false, err
	}

	if tokenDTO.Role != requiredRole {
		return false, nil
	}

	return true, nil
}
