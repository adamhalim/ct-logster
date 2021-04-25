module logster

go 1.16

require (
	github.com/google/certificate-transparency-go v1.1.1
	github.com/joho/godotenv v1.3.0
	github.com/robfig/cron v1.2.0
	go.mongodb.org/mongo-driver v1.5.1
	golang.org/x/crypto v0.0.0-20210415154028-4f45737414dc
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	revocado v0.0.0
)

replace revocado => ../revocado
