package interfaces

import "Test_Task_Jwt/models/dto"

type DbConnector interface {
	CreateTokenRecord(record *dto.TokenRecord) error
	RefreshHash(guid string, hash string) error
	GetRecordByGuid(guid string) (*dto.TokenRecord, error)
	Cleanup()
}
