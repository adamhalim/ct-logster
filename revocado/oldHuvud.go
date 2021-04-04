package revocado


import (
	"fmt"
	"os"

	"github.com/robfig/cron"
	log "github.com/sirupsen/logrus"
	"time"

	"github.com/joho/godotenv"
	/*"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	*/
)
var dbUsername, dbPassword, dbIp, dbPort string;
// Loads .env file
func init() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
	}
	dbUsername = os.Getenv("USERNAME")
	dbPassword = os.Getenv("PASSWORD")
	dbIp = os.Getenv("IP_ADDRESS")
	dbPort = os.Getenv("PORT")

	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
}

func main() {
	//cronjobs start
	log.Info("Create new cron")
	c := cron.New()
	c.AddFunc("/1 * * * *", gruntWork)

	// Start cron with one scheduled job
	log.Info("Start cron")
	c.Start()
	printCronEntries(c.Entries())

	time.Sleep(5 * time.Minute)
}

//Should should be scheduled by main as cronjob?
func gruntWork(){
	log.Info("Started Gruntwork!")
	//Get all DB entries for this hour.

	//Call go GetOCSP or CTL for every entry.

	//If new status update DB and append new results to db
}

func printCronEntries(cronEntries []cron.Entry) {
	log.Infof("Cron Info: %+v\n", cronEntries)
}
