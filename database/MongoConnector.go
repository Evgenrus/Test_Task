package database

import (
	"Test_Task_Jwt/models/dto"
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoConnector struct {
	client     *mongo.Client
	Collection *mongo.Collection
	ctx        context.Context
}

func CreateMongoConnector(uri string, dbName string, colName string) (*MongoConnector, error) {
	option := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(context.TODO(), option)
	if err != nil {
		return nil, err
	}

	collection := client.Database(dbName).Collection(colName)

	return &MongoConnector{
		client:     client,
		Collection: collection,
		ctx:        context.TODO(),
	}, nil
}

func (c *MongoConnector) CreateTokenRecord(record *dto.TokenRecord) error {
	if len(record.Guid) == 0 || len(record.RefreshHash) == 0 {
		return errors.New("GUID or hash cannot be empty")
	}

	err := c.Collection.FindOne(c.ctx, bson.M{"_id": record.Guid}).Err()
	if err == nil {
		return errors.New("this user already exists")
	} else if !errors.Is(err, mongo.ErrNoDocuments) {
		return err
	}

	_, err = c.Collection.InsertOne(c.ctx, bson.M{"_id": record.Guid, "refresh_token": record.RefreshHash})

	return err
}

func (c *MongoConnector) RefreshHash(guid string, hash string) error {
	if len(guid) == 0 || len(hash) == 0 {
		return errors.New("GUID or hash cannot be empty")
	}

	filter := bson.D{{"_id", guid}}
	update := bson.D{
		{"$set", bson.D{
			{"refresh_hash", hash},
		},
		}}

	updated, err := c.Collection.UpdateOne(c.ctx, filter, update)
	if updated.ModifiedCount == 0 {
		return errors.New("no matches")
	}

	return err
}

func (c *MongoConnector) GetRecordByGuid(guid string) (*dto.TokenRecord, error) {
	if len(guid) == 0 {
		return nil, errors.New("guid cannot be empty")
	}

	var tokenRecord dto.TokenRecord

	err := c.Collection.FindOne(c.ctx, bson.D{{"_id", guid}}).Decode(&tokenRecord)
	if err != nil {
		return nil, err
	}

	return &tokenRecord, nil
}

func (c *MongoConnector) Cleanup() {
	c.client.Disconnect(c.ctx)
}
