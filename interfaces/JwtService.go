package interfaces

import (
	"Test_Task_Jwt/models"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type JwtService interface {
	CreateToken(guid string, expires time.Time, key []byte) (string, error)
	GenerateTokenPair(guid string) (*models.TokenPair, error)
	CheckToken(token string, keyEnv string) (jwt.Claims, error)
	RefreshToken(refresh string) (*models.TokenPair, error)
}
