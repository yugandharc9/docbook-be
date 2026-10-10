#!/bin/bash
set -e

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bootstrap cmd/main.go
zip package.zip bootstrap
aws lambda update-function-code \
  --region ap-south-1 \
  --function-name docbook-be \
  --zip-file fileb://package.zip
rm bootstrap
echo "Deployed!"
