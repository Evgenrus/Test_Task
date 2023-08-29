package services

import (
	"Test_Task_Jwt/models/dto"
	"Test_Task_Jwt/models/mocks"
	"encoding/base64"
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
	"os"
	"strings"
	"testing"
	"time"
)

var (
	correctRefToken  = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwiZXhwIjoxNTU1NTU1NTU1NX0.bIYFNTlIddyBLbg427sT8cZDKW2wJN4gnAJKKpJNrQrwQScfD_FadTsAQMcQR-ZeCCgf8UjR_2HNFt5YVguBBw"
	outdatedRefToken = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwiZXhwIjoxNTU1NTU1NTV9.Xi4_Wvoh3W-OqrmFGhXEql0HpxBa3Wu0lYrrL4TmSFeuh9HVT0IWwvXMpAuYpKnMJVpp1eat-mmUcOFRdoGz4Q"
	invalidRefToken  = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwiZXhwIjoxNTU1NTU1NTV9.Xi4_Wvoh3W-OqrmFGhXEql0HpxBa3Wu0lYrrL4TmSFeuh9HVT0IWwvXMpAuYpKnMJVpp1eat-OFRdoGz4Q"
)

func initTests() *JwtServiceImpl {
	connectorMocks := mocks.DbConnectorMocks{}

	hash, _ := bcrypt.GenerateFromPassword([]byte(correctRefToken), bcrypt.DefaultCost)
	hashString := string(hash)
	//jwtHash, _ := bcrypt.GenerateFromPassword([]byte(correctAccessToken), bcrypt.DefaultCost)

	connectorMocks.On("CreateTokenRecord", &dto.TokenRecord{Guid: "1234", RefreshHash: hashString}).Return(nil)
	connectorMocks.On("CreateTokenRecord", &dto.TokenRecord{Guid: "", RefreshHash: hashString}).Return(errors.New("empty guid"))
	connectorMocks.On("CreateTokenRecord", &dto.TokenRecord{Guid: "1234", RefreshHash: hashString}).Return(errors.New("empty hash"))
	connectorMocks.On("CreateTokenRecord", mock.Anything).Return(nil)

	connectorMocks.On("RefreshHash", mock.Anything, mock.Anything).Return(nil)

	sign := strings.Split(correctRefToken, ".")[2]
	signHash, _ := bcrypt.GenerateFromPassword([]byte(sign), bcrypt.DefaultCost)
	connectorMocks.On("GetRecordByGuid", "1234").Return(&dto.TokenRecord{Guid: "1234", RefreshHash: string(signHash)}, nil)

	os.Setenv("JWT_KEY", "123456")
	os.Setenv("REF_KEY", "098765")

	return &JwtServiceImpl{dbConn: &connectorMocks}
}

func TestJwtService_CreateToken(t *testing.T) {
	service := initTests()

	cases := []struct {
		name     string
		guid     string
		expires  time.Time
		key      []byte
		expected bool
	}{
		{
			name:     "Correct arguments",
			guid:     "1234",
			expires:  time.Now().Add(15 * time.Minute),
			key:      []byte("simpleKey"),
			expected: true,
		},
		{
			name:     "Wrong date",
			guid:     "1234",
			expires:  time.Now().Add(-15 * time.Minute),
			key:      []byte("simpleKey"),
			expected: false,
		},
		{
			name:     "Empty key",
			guid:     "1234",
			expires:  time.Now().Add(15 * time.Minute),
			key:      []byte(""),
			expected: false,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := service.CreateToken(testCase.guid, testCase.expires, testCase.key)
			assert.Equal(t, err == nil, testCase.expected)
		})
	}
}

func TestJwtService_GenerateTokenPair(t *testing.T) {
	service := initTests()

	cases := []struct {
		name     string
		guid     string
		expected bool
	}{
		{name: "Empty guid", guid: "", expected: false},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := service.LoginUser(testCase.guid)
			assert.Equal(t, err == nil, testCase.expected)
		})
	}
}

func TestJwtService_CheckToken(t *testing.T) {
	service := initTests()

	cases := []struct {
		name     string
		token    string
		keyEnv   string
		expected bool
	}{
		{
			"correct refresh token",
			correctRefToken,
			"REF_KEY",
			true,
		},
		{
			"outdated refresh token",
			outdatedRefToken,
			"REF_KEY",
			false,
		},
		{
			"incorrect refresh token sign",
			invalidRefToken,
			"REF_KEY",
			false,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := service.CheckToken(testCase.token, testCase.keyEnv)
			assert.Equal(t, err == nil, testCase.expected)
		})
	}
}

func TestJwtService_RefreshToken(t *testing.T) {
	service := initTests()

	cases := []struct {
		name     string
		token    string
		expected bool
	}{
		{"correct token", correctRefToken, true},
		{"outdated token", outdatedRefToken, false},
		{"invalid token", invalidRefToken, false},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			base := base64.StdEncoding.EncodeToString([]byte(correctRefToken))
			_, err := service.RefreshToken(base)
			assert.Equal(t, err == nil, testCase.expected)
		})
	}
}
