package database

import (
	"Test_Task_Jwt/models/dto"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"testing"
)

func TestMongoConnector_CreateTokenRecord(t *testing.T) {
	conn, cleanup := createConnector(t)
	defer cleanup()

	cases := []struct {
		name     string
		guid     string
		hash     []byte
		expected bool
	}{
		{"Registering user to db", "1234", []byte("refresh1234"), true},
		{"Trying to reregister user", "1234", []byte("refresh1234"), false},
		{"Adding another user with empty hash", "1111", []byte(""), false},
		{"Adding another user", "1111", []byte("somerefresh"), true},
		{"Adding third user with empty GUID", "", []byte("empty"), false},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := conn.CreateTokenRecord(&dto.TokenRecord{
				Guid:        testCase.guid,
				RefreshHash: testCase.hash,
			})
			assert.Equal(t, err == nil, testCase.expected)
		})
	}
}

func TestMongoConnector_RefreshHash(t *testing.T) {
	conn, cleanup := createConnector(t)
	defer cleanup()

	_, err := conn.Collection.InsertOne(conn.ctx, bson.M{"_id": "1234", "refresh_hash": []byte("1234token")})
	assert.NoError(t, err)

	cases := []struct {
		name     string
		guid     string
		hash     []byte
		expected bool
	}{
		{"Trying to insert empty hash", "1234", []byte(""), false},
		{"Refreshing for existing user", "1234", []byte("newTokenHash"), true},
		{"Refreshing for not existing user", "1111", []byte("shouldnt work"), false},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := conn.RefreshHash(testCase.guid, testCase.hash)
			assert.Equal(t, err == nil, testCase.expected)
		})
	}
}

func createConnector(t *testing.T) (*MongoConnector, func()) {
	conn, err := CreateMongoConnector("mongodb://localhost:27017", "test_user", "userTokens")
	assert.NoError(t, err)
	return conn, func() {
		conn.Collection.Database().Drop(conn.ctx)
		conn.Cleanup()
	}
}
