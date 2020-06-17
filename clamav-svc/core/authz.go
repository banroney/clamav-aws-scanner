package main

import (
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

type ServiceAuth struct {
	Service string
	Roles   []string
}

func getDDBSession() *dynamodb.DynamoDB {
	// Initialize a session that the SDK will use to load
	// credentials from the shared credentials file ~/.aws/credentials
	// and region from the shared configuration file ~/.aws/config.
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	// Create DynamoDB client
	svc := dynamodb.New(sess)
	return svc
}

func getRolesForService(serviceName string) ([]string, *error) {
	svc := getDDBSession()

	tableName := os.Getenv("ROLES_DYNAMOTABLE")

	result, err := svc.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"service": {
				S: aws.String(serviceName),
			},
		},
	})
	if err != nil {
		fmt.Println(err.Error())
		return nil, &err
	} else {
		serviceauth := ServiceAuth{}

		err = dynamodbattribute.UnmarshalMap(result.Item, &serviceauth)
		if err != nil {
			panic(fmt.Sprintf("Failed to unmarshal Record"))
		}
		return serviceauth.Roles, nil
	}
}
