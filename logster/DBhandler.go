package main

import (
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)


var dbUsername, dbPassword, dbIp, dbPort, dbName, dbCollection, dbChainCollection string

// Loads .env file
func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
		os.Exit(0)
	}
	dbUsername = os.Getenv("USERNAME")
	dbPassword = os.Getenv("PASSWORD")
	dbIp = os.Getenv("IP_ADDRESS")
	dbPort = os.Getenv("PORT")
	dbName = os.Getenv("DB")
	dbCollection = os.Getenv("MAIN_COLLECTION")
	dbChainCollection = os.Getenv("CERT_COLLECTION")
}

// Makes one insertion into MongoDB
func InsertIntoDB(client mongo.Client, cancel context.CancelFunc, cert CertInfo) {

	collection := client.Database("dev").Collection("certTestThree")
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	//Actual insert to MongoDB. Could possibly be done in batches for better performance
	_, err := collection.InsertOne(ctx, cert)
	if err != nil {
		fmt.Print("Error inserting.")
	}
}

// Makes one insertion into MongoDB
func InsertChainCertIntoDB(client mongo.Client, cancel context.CancelFunc, chain ChainCertPem) (objectID string, err error) {

	// If, for any reason, the Chain certificate is empty,
	// we return.
	if chain.PEM == "" {
		fmt.Printf("Error inserting: Chain is empty.\n")
		return
	}
	// We check if the CertChainPem already is stored in the DB.
	chainInDB, err := isChainInDB(chain.PEM, &client)
	if err != nil {
		return "", err
	}
	if chainInDB != "" {
		fmt.Printf("Cert is already in DB\n")
		return chainInDB, nil
	}

	// For unique chain certs, we push them to our DB to the dbChainCollection
	collection := client.Database(dbName).Collection(dbChainCollection)
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	//Actual insert to MongoDB. Could possibly be done in batches for better performance
	res, err := collection.InsertOne(ctx, chain)
	if err != nil {
		return "", err
	}
	// If we are successful inserting, we return the
	id := res.InsertedID
	idString := id.(primitive.ObjectID).Hex()
	return idString, nil
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

	col := client.Database(dbName).Collection(dbCollection)
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
						_, chain, err := GetChainCert(indexStr, urlStr)
						if err != nil {
							fmt.Printf("Error getting Cert Chain: %v", err.Error())
							return
						}
						certificates, err := DecodePemsToX509(chain)
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

func IterateBlock(blockTime int){
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

	databases, err := client.ListDatabaseNames(ctx, bson.M{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(databases)

	// Pass these options to the Find method
	findOptions := options.Find()
	findOptions.SetLimit(20)

	// Here's an array in which you can store the decoded documents
	var res []*CertInfo

	col := client.Database(dbName).Collection(dbCollection)

	// Passing bson.D{{}} as the filter matches all documents in the collection
	cur, err := col.Find(context.TODO(), bson.D{{"Time", blockTime}}, findOptions)
	if err != nil {
		fmt.Println("Error when collecting")
	}

	// Finding multiple documents returns a cursor
	// Iterating through the cursor allows us to decode documents one at a time
	for cur.Next(context.TODO()) {

		// create a value into which the single document can be decoded
		var elem CertInfo
		err := cur.Decode(&elem)
		if err != nil {
			log.Fatal(err)
		}

		res = append(res, &elem)
	}
	if err := cur.Err(); err != nil {
		log.Fatal(err)
	}

	// Close the cursor once finished
	cur.Close(context.TODO())

	fmt.Printf("Found multiple documents (array of pointers): %+v\n", res)

	for _,entry := range res{
		fmt.Println(entry)
	}
}

// Checks whether a certificate already is in the cert chain DB.
// We run this for every cert in the chain to avoid saving duplicates.
// (A lot of certificates share chain certs)
func isChainInDB(chainCert string, client *mongo.Client) (objectID string, err error) {
	col := client.Database(dbName).Collection(dbChainCollection)
	cursor, err := col.Find(context.Background(), bson.M{"pem": chainCert})
	if err != nil {
		return "", err
	}

	// If we found something, we return the
	// Mongo object ID string
	for cursor.Next(context.Background()) {
		var result bson.M
		err := cursor.Decode(&result)
		if err != nil {
			fmt.Printf("Error decoding cert.\n")
			return "", err
		}
		// We convert the result to a ObjectID and return
		// the Object ID string
		objectID := result["_id"]
		stringObjectID := objectID.(primitive.ObjectID).Hex()
		return stringObjectID, nil
	}
	return "", nil
}