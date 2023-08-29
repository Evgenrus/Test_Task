package services

import (
	"Test_Task_Jwt/interfaces"
	"Test_Task_Jwt/models"
	"Test_Task_Jwt/models/dto"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"os"
	"strings"
	"time"
)

type JwtServiceImpl struct {
	dbConn interfaces.DbConnector
}

func CreateJwtServices(db interfaces.DbConnector) *JwtServiceImpl {
	return &JwtServiceImpl{dbConn: db}
}

func (s *JwtServiceImpl) CreateToken(guid string, expires time.Time, key []byte) (string, error) {
	if len(key) == 0 {
		return "", errors.New("key cannot be empty")
	}

	if expires.Unix() < time.Now().Unix() {
		return "", errors.New("wrong 'ExpiresAt'")
	}

	claims := &jwt.RegisteredClaims{
		Subject:   guid,
		ExpiresAt: jwt.NewNumericDate(expires),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(key)
}

func (s *JwtServiceImpl) SaveNewTokenRecord(guid string) (*models.TokenPair, error) {
	tokens, err := s.generateTokenPair(guid)
	if err != nil {
		return nil, err
	}

	sign := strings.Split(tokens.RefreshToken, ".")[2]

	base := getHashString(sign)

	err = s.dbConn.CreateTokenRecord(&dto.TokenRecord{Guid: guid, RefreshHash: base})
	if err != nil {
		return nil, err
	}
	return tokens, err
}

func (s *JwtServiceImpl) generateTokenPair(guid string) (*models.TokenPair, error) {
	accKey := []byte(os.Getenv("JWT_KEY"))
	refKey := []byte(os.Getenv("REF_KEY"))

	accExp := time.Now().Add(15 * time.Minute)
	refExp := time.Now().Add(25 * 24 * time.Hour)

	accToken, err := s.CreateToken(guid, accExp, accKey)
	if err != nil {
		return nil, err
	}
	refToken, err := s.CreateToken(guid, refExp, refKey)
	if err != nil {
		return nil, err
	}

	return &models.TokenPair{
		AccessToken:  accToken,
		RefreshToken: refToken,
	}, nil
}

func (s *JwtServiceImpl) CheckToken(token string, keyEnv string) (jwt.Claims, error) {
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

	return parsed.Claims, nil
}

func (s *JwtServiceImpl) RefreshToken(refresh string) (*models.TokenPair, error) {
	claims, err := s.CheckToken(refresh, "REF_KEY")
	if err != nil {
		return nil, err
	}

	subject, err := claims.GetSubject()
	if err != nil {
		return nil, err
	}

	record, err := s.dbConn.GetRecordByGuid(subject)
	if err != nil {
		return nil, err
	}

	sign := strings.Split(refresh, ".")[2]

	err = bcrypt.CompareHashAndPassword([]byte(record.RefreshHash), []byte(sign))
	if err != nil {
		return nil, err
	}

	tokens, err := s.generateTokenPair(subject)
	if err != nil {
		return nil, err
	}

	hash := getHashString(tokens.RefreshToken)

	err = s.dbConn.RefreshHash(subject, hash)
	if err != nil {
		return nil, err
	}

	return &models.TokenPair{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func getHashString(refresh string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(refresh), bcrypt.DefaultCost)
	return string(hash)
}
