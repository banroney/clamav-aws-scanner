# AWSMalware Scanner

There are 2 modules in this repository, the first one implements a malware service scanner using Elastic Container Services and Fargate. The second one implements a Lambda Function that uses the service to run S3 contents in runtime using a trusted role. 

## 1. Malware Scanner Service

## 1.1 Overview
The following blog describes Hashicorp Vault Integration in AWS. It focusses on three methods of accessing secrets in the
Vault. However the following implementations has a few assumptions as below. All the following options

## 1.2 Architecture

The following picture depicts the malware scanner architecture in AWS

![Architecture Diagram](/images/clamav-svc.svg)

The above diagram depicts 2 components deployable in 2 different AWS accounts. 

### Component 1 - The scanner service (/clamav-svc)
This represents the scanner service written in Go and deployed in AWS Elastic Container Service. There are 3 endpoints, 2 of which are deployed in this repository. The services are as follows

#### - Scan 
This endpoint takes an input of a file and scans it and returns a result specifying if the file is safe or not. If not, the return description includes the malware description. The following is an example input for the API endpoint. The endpoint needs to be authenticated using AWS Signature V4 methods. A sample usage is shown in python 3.8 in the lambda module.

This endpoint needs an authorized role as per the DynamoDB entry in the table `clamav_permissions`. The entry that it looks for is `{ "arn:xxxx:xxxxxxx:xxxxxxxx" : { "SS" : [      ""    ]  }}`. Replacing the ARN with the corresponding role will allow the role to be used with the scanner. 



    POST /scan HTTP/1.1
    Host: clamav-scanner.yourhost.com
    X-Amz-Date: 20200720T154445Z
    Authorization: AWS4-HMAC-SHA256 Credential=XXXXXXXXXXXXXXXX/20200720/us-east-1/sts/aws4_request, SignedHeaders=host;x-amz-date, Signature=fc96e78b8c6f45fb73ae73004ac01f4a181545e2b93c51f0c6289ae558f6225aContent-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

    ----WebKitFormBoundary7MA4YWxkTrZu0gW
    Content-Disposition: form-data; name="file"; filename="sample_filetxt"
    Content-Type: application/pdf

    (data)
    ----WebKitFormBoundary7MA4YWxkTrZu0gW
    Content-Disposition: form-data; name="service"

    https://sts.amazonaws.com
    ----WebKitFormBoundary7MA4YWxkTrZu0gW

#### - Version
The version endpoint can be used to test the version details of the service and checking health. The API usage is as follows


    GET /version HTTP/1.1
    Host: clamav-scanner.youhost.com
    Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

    ----WebKitFormBoundary7MA4YWxkTrZu0gW
    
### Component 2 - The Lambda Function (/clamav-lambda)
This component as shown in the diagram can be deployed in a separate account and would be used to access the scanner service. The usage is tied to an event such as creation of an object in S3.

In case, an infected file is found, it quarantines the file to a quarantine bucket along with some information in the metadata of the s3 object. 

    
## 1.3 Deployment - 

## Component 1 - ClamAV Service

In order to deploy this component, please go to AWS> CloudFormation
Use the template.yaml to create teh stack. Create teh input and wait for all the components to be created and deployed. The outputs will display the endpoint for the 


## Component 2 - Lambda Service





