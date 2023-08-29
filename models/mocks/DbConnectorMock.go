package mocks

import (
	"Test_Task_Jwt/models/dto"
	"errors"
	"github.com/stretchr/testify/mock"
)

type DbConnectorMocks struct {
	mock.Mock
}

func (m *DbConnectorMocks) RefreshHash(guid string, hash string) error {
	args := m.Called(guid, hash)
	return args.Error(0)
}

func (m *DbConnectorMocks) GetRecordByGuid(guid string) (*dto.TokenRecord, error) {
	args := m.Called(guid)
	return args.Get(0).(*dto.TokenRecord), args.Error(1)
	//return &dto.TokenRecord{Guid: "1234", RefreshHash: []byte("1234")}, args.Error(1)
}

func (m *DbConnectorMocks) Cleanup() {
	return
}

func (m *DbConnectorMocks) CreateTokenRecord(record *dto.TokenRecord) error {
	args := m.Called(record)
	if len(record.Guid) != 0 && len(record.RefreshHash) != 0 {
		return args.Error(0)
	} else {
		return errors.New("empty guid or hash")
	}

}
