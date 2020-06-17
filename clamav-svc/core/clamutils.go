package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	ioutil "io/ioutil"
	"net/http"
	"os"
	"strings"
)

type GetCallerIdentityResponse struct {
	XMLName                 xml.Name                  `xml:"GetCallerIdentityResponse"`
	GetCallerIdentityResult []GetCallerIdentityResult `xml:"GetCallerIdentityResult"`
	ResponseMetadata        []ResponseMetadata        `xml:"ResponseMetadata"`
}

type GetCallerIdentityResult struct {
	Arn     string `xml:"Arn"`
	UserId  string `xml:"UserId"`
	Account string `xml:"Account"`
}

type ResponseMetadata struct {
	RequestId string `xml:"RequestId"`
}

type iamEntity struct {
	Partition     string
	AccountNumber string
	Type          string
	Path          string
	FriendlyName  string
	SessionInfo   string
}

func (e *iamEntity) canonicalArn() string {
	entityType := e.Type
	// canonicalize "assumed-role" into "role"
	if entityType == "assumed-role" {
		entityType = "role"
	}

	return fmt.Sprintf("arn:%s:iam::%s:%s/%s", e.Partition, e.AccountNumber, entityType, e.FriendlyName)
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func validateMac(message string, messageMAC string) bool {
	expectedMAC := genHmac(message)
	return messageMAC == expectedMAC
}

func genHmac(message string) string {
	mac := hmac.New(sha256.New, readKey())
	mac.Write([]byte(message))
	expectedMAC := mac.Sum(nil)
	b64hmac := base64.StdEncoding.EncodeToString(expectedMAC)
	return b64hmac
}

func parseIamArn(iamArn string) (*iamEntity, error) {
	// iamArn should look like one of the following:
	// 1. arn:aws:iam::<account_id>:<entity_type>/<UserName>
	// 2. arn:aws:sts::<account_id>:assumed-role/<RoleName>/<RoleSessionName>
	// if we get something like 2, then we want to transform that back to what
	// most people would expect, which is arn:aws:iam::<account_id>:role/<RoleName>
	var entity iamEntity
	fullParts := strings.Split(iamArn, ":")
	if len(fullParts) != 6 {
		return nil, fmt.Errorf("unrecognized arn: contains %d colon-separated parts, expected 6", len(fullParts))
	}
	if fullParts[0] != "arn" {
		return nil, fmt.Errorf("unrecognized arn: does not begin with \"arn:\"")
	}
	// normally aws, but could be aws-cn or aws-us-gov
	entity.Partition = fullParts[1]
	if fullParts[2] != "iam" && fullParts[2] != "sts" {
		return nil, fmt.Errorf("unrecognized service: %v, not one of iam or sts", fullParts[2])
	}
	// fullParts[3] is the region, which doesn't matter for AWS IAM entities
	entity.AccountNumber = fullParts[4]
	// fullParts[5] would now be something like user/<UserName> or assumed-role/<RoleName>/<RoleSessionName>
	parts := strings.Split(fullParts[5], "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("unrecognized arn: %q contains fewer than 2 slash-separated parts", fullParts[5])
	}
	entity.Type = parts[0]
	entity.Path = strings.Join(parts[1:len(parts)-1], "/")
	entity.FriendlyName = parts[len(parts)-1]
	// now, entity.FriendlyName should either be <UserName> or <RoleName>
	switch entity.Type {
	case "assumed-role":
		// Check for three parts for assumed role ARNs
		if len(parts) < 3 {
			return nil, fmt.Errorf("unrecognized arn: %q contains fewer than 3 slash-separated parts", fullParts[5])
		}
		// Assumed roles don't have paths and have a slightly different format
		// parts[2] is <RoleSessionName>
		entity.Path = ""
		entity.FriendlyName = parts[1]
		entity.SessionInfo = parts[2]
	case "user":
	case "role":
	case "instance-profile":
	default:
		return &iamEntity{}, fmt.Errorf("unrecognized principal type: %q", entity.Type)
	}
	return &entity, nil
}

func parseGetCallerIdentityResponse(response string) (GetCallerIdentityResponse, error) {
	decoder := xml.NewDecoder(strings.NewReader(response))
	result := GetCallerIdentityResponse{}
	err := decoder.Decode(&result)
	return result, err
}

func isCallerAuthorized(r *http.Request) (bool, error) {
	allowedRoles, _ := getRolesForService("scan")
	//allowedRoles := strings.Split(os.Getenv("ALLOWED_ARNS"), ",")
	callerIdentity, error := getCallerIdentity(r)

	if error == nil && callerIdentity != nil {
		iamEntity, iamErr := parseIamArn(callerIdentity.Arn)
		if iamErr == nil {
			iamArn := iamEntity.canonicalArn()
			if stringInSlice(iamArn, allowedRoles) {
				return true, nil
			}
			return false, errors.New("Caller " + callerIdentity.Arn + " not authorized to perform.")
		}
		return false, iamErr
	}
	return false, error
}

func getCallerIdentity(r *http.Request) (*GetCallerIdentityResult, error) {

	url := r.Header.Get("service")
	method := "GET"

	payload := strings.NewReader("")

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization", r.Header.Get("Authorization"))
	req.Header.Add("x-amz-date", r.Header.Get("x-amz-date"))
	if r.Header.Get("x-amz-security-token") != "" {
		req.Header.Add("x-amz-security-token", r.Header.Get("x-amz-security-token"))
	}

	res, err := client.Do(req)
	defer res.Body.Close()
	responseBody, err := ioutil.ReadAll(res.Body)

	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf(string(responseBody))
	}
	callerIdentityResponse, err := parseGetCallerIdentityResponse(string(responseBody))
	if err != nil {
		return nil, fmt.Errorf("error parsing STS response")
	}
	return &callerIdentityResponse.GetCallerIdentityResult[0], nil

}

func readKey() []byte {
	key := os.Getenv("HMACKEY")
	return []byte(key)
}
