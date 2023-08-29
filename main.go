package main

import (
	"Test_Task_Jwt/database"
	"Test_Task_Jwt/server"
	"Test_Task_Jwt/services"
	"log"
	"os"
)

func main() {

	mongoUri := os.Getenv("MONGO_URI")
	mongoDb := os.Getenv("MONGO_DB")
	mongoCol := os.Getenv("MONGO_COL")

	mongoConn, err := database.CreateMongoConnector(mongoUri, mongoDb, mongoCol)
	if err != nil {
		log.Fatal(err)
	}

	service := services.CreateJwtServices(mongoConn)

	serv := server.CreateServer(service)

	serv.Start()
}
