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
const database, dbCollection = "dev", "certTestRee"

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

// Makes one insertion into MongoDB
func InsertIntoDB(client mongo.Client, ctx context.Context, cancel context.CancelFunc, cert CertInfo) {

	collection := client.Database(database).Collection(dbCollection)
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	//Actual insert to MongoDB. Could possibly be done in batches for better performance
	_, err := collection.InsertOne(ctx, cert)
	if err != nil {
		fmt.Print("Error inserting.")
	}
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

	col := client.Database(database).Collection(dbCollection)
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
						_, chain, err := GetCertChain(indexStr, urlStr)
						if err != nil {
							fmt.Printf("Error getting Cert Chain: %v", err.Error())
							return
						}
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

	col := client.Database(database).Collection(dbCollection)

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
//status should only be: Good, Unknown, Revoked or Unexcpected.
//Unexcpeted will probably be handled earlier in code. But should still be handled here too
func AppendNewStatus(client mongo.Client, cancel context.CancelFunc, certID string, changeTime time.Time, status string){
    collection := client.Database("dev").Collection(dbCollection)
    ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()


    // Read Once
    var res CertInfo

    err := collection.FindOne(ctx, bson.M{"_id": certID}).Decode(&res)
    if err != nil{
        fmt.Println("Error finding certID")
        return
    }

    var update bool = false
    s := len(res.Changes)

    if s > 0{
        lastElem := res.Changes[s-1]
        if lastElem.Status != status{
            newEntry := StatusUpdate{status, changeTime}
            res.Changes = append(res.Changes, newEntry)
            update = true
        }
    }else {
        if status != "Good"{
            newEntry := StatusUpdate{status, changeTime}
            res.Changes = append(res.Changes, newEntry)
            update = true
        }
    }

    //Actual update to MongoDB. Could possibly be done in batches for better performance
    if update{
        filter := bson.M{"_id":certID}
        change, err := bson.Marshal(res)
        if err != nil {
            fmt.Println("Error when using bson.Marshal.")
            fmt.Println(err)
        }

        _, err = collection.UpdateOne(ctx, filter, change)
        if err != nil{
            fmt.Println("Error when trying to update document")
            fmt.Println(err)
        }
    }
}
