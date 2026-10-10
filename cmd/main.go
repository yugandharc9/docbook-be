package main

import (
	"context"
	"log"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/aws-lambda-go-api-proxy/core"
	"github.com/awslabs/aws-lambda-go-api-proxy/gorillamux"
	"github.com/yugandharc9/docbook-be/internal"
	"github.com/yugandharc9/refinery/api"
)

var gorillaLambda *gorillamux.GorillaMuxAdapter

func Init() {
	r, db, srv, err := api.Init()
	if err != nil {
		log.Fatal(err.Error())
	}

	payCtx := internal.NewPaymentCtx(db)
	payCtx.Register(r)

	oneTapCtx := internal.NewOneTapCtx(db)
	oneTapCtx.Register(r)

	profileCtx := internal.NewProfileCtx(db)
	profileCtx.Register(r)

	if os.Getenv("AWS_LAMBDA_RUNTIME_API") == "" {
		log.Println("Starting http server...")
		log.Fatal(srv.ListenAndServe())
	} else {
		gorillaLambda = gorillamux.New(r)
	}
}

func Handler(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	rr, err := gorillaLambda.ProxyWithContext(ctx, *core.NewSwitchableAPIGatewayRequestV2(&req))
	return *rr.Version2(), err
}

func main() {
	Init()
	lambda.Start(Handler)
}
