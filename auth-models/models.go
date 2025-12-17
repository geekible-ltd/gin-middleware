package authmodels

type TokenDTO struct {
	Sub       any    `json:"sub"`
	CompanyID any    `json:"company_id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Role      string `json:"role"`
	Exp       int64  `json:"exp"`
	Iat       int64  `json:"iat"`
}
