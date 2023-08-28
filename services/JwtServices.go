package services

import (
	"Test_Task_Jwt/database"
	"Test_Task_Jwt/models"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"time"
)

type JwtService struct {
	dbConn *database.MongoConnector
}

func CreateJwtServices(db *database.MongoConnector) *JwtService {
	return &JwtService{dbConn: db}
}

func (s *JwtService) CreateTokens(guid string, expires time.Time, key []byte) (string, error) {
	claims := &jwt.RegisteredClaims{
		Subject:   guid,
		ExpiresAt: jwt.NewNumericDate(expires),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(key)
}

func (s *JwtService) GenerateTokenPair(guid string) (*models.TokenPair, error) {
	accKey := []byte(os.Getenv("JWT_KEY"))
	refKey := []byte(os.Getenv("REF_KEY"))

	accExp := time.Now().Add(15 * time.Minute)
	refExp := time.Now().Add(25 * 24 * time.Hour)

	accToken, err := s.CreateTokens(guid, accExp, accKey)
	if err != nil {
		return nil, err
	}
	refToken, err := s.CreateTokens(guid, refExp, refKey)
	if err != nil {
		return nil, err
	}

	return &models.TokenPair{
		AccessToken:  accToken,
		RefreshToken: refToken,
	}, nil
}

func (s *JwtService) CheckToken(token string, keyEnv string) (jwt.Claims, error) {
	parsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("error in parsing token")
		}
		return []byte(os.Getenv(keyEnv)), nil
	})

	if !parsed.Valid {
		return nil, err
	}

	expDate, err := parsed.Claims.GetExpirationTime()
	if err != nil {
		return nil, err
	}

	if expDate.Unix() < time.Now().Unix() {
		return nil, errors.New("token has been expired")
	}

	tokenBytes := []byte(token)

	//record := s.dbConn.GetRecordByGuid(subject)
	//if err = bcrypt.CompareHashAndPassword(record.RefreshHash, tokenBytes); err != nil {
	//    return nil, err
	//}

	return parsed.Claims, nil
}

func (s *JwtService) RefreshToken(refresh string) (*models.TokenPair, error) {
	claims, err := s.CheckToken(refresh, "REF_KEY")
	if err != nil {
		return nil, err
	}

	subject, err := claims.GetSubject()
	if err != nil {
		return nil, err
	}

	return s.GenerateTokenPair(subject)
}
