package dto

type TokenRecord struct {
	Guid        string `bson:"_id"`
	RefreshHash string `bson:"refresh_hash"`
}
