package dto

type TokenRecord struct {
	Guid        string `bson:"_id"`
	RefreshHash []byte `bson:"refresh_hash"`
}
