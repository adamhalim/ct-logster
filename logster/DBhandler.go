package main

import (
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"context"
	"time"
	"fmt"
	"log"
	"os"
	"sync"
)


var dbUsername, dbPassword, dbIp, dbPort string
const database, collection = "dev", "certTestTwo"

// Loads .env file
func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	dbUsername = os.Getenv("USERNAME")
	dbPassword = os.Getenv("PASSWORD")
	dbIp = os.Getenv("IP_ADDRESS")
	dbPort = os.Getenv("PORT")
}

func main() {
	IterateAllCerts()
}

// This will iterate though all certs in 
// database.collection and currently runs 
// GetCertChain() on all documents.
func IterateAllCerts() {
	// Establish connection to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	uri := "mongodb://" + dbIp + ":" + dbPort
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))

	//disconnects the db when exiting main.
	defer func() {
		if err = client.Disconnect(ctx); err != nil {
			panic(err)
		}
	}()

	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = client.Ping(ctx, readpref.Primary())

	fmt.Println("Connected to MongoDB Server: " + dbIp + ".")

	col := client.Database(database).Collection(collection)
	cursor, err := col.Find(context.TODO(), bson.D{})
	if err != nil {
		fmt.Println("Finding all documents ERROR:", err)
		defer cursor.Close(ctx)
	} else {
		// Creates a WaitGroup that will wait for all 
		// routines to finish before closing program
		var wg sync.WaitGroup
		for cursor.Next(ctx) {
			var result bson.M
			err := cursor.Decode(&result)
			// If there is a cursor.Decode error
			if err != nil {
				fmt.Println("cursor.Next() error:", err)
			} else {
				index := result["certIndex"]
				url := result["ctLog"]

				indexStr := fmt.Sprintf("%v", index)
				urlStr := fmt.Sprintf("%v", url)
				if url != "" {
					wg.Add(1)
					go func() {
						defer wg.Done()
						_, chain := GetCertChain(indexStr, urlStr)
						certificates, err := DecodePem(chain)
						if err != nil {
							fmt.Printf("%s", err.Error())
						}
						if certificates == nil {
							fmt.Print("No certs decoded.\n")
						} else {

						}
					}()
				}
			}
		}
		wg.Wait()
	}
}

