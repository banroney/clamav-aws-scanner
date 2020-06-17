#!/bin/bash
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 951145066533.dkr.ecr.us-east-1.amazonaws.com
docker build -t sf-epics/clamav-rest .
docker tag sf-epics/clamav-rest:latest 951145066533.dkr.ecr.us-east-1.amazonaws.com/sf-epics/clamav-rest:latest
docker push 951145066533.dkr.ecr.us-east-1.amazonaws.com/sf-epics/clamav-rest:latest