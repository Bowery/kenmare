// Copyright 2014 Bowery, Inc.
package main

import (
	"flag"
	"os"
	"path/filepath"

	"github.com/Bowery/gopackages/config"
	"github.com/Bowery/gopackages/email"
	"github.com/Bowery/gopackages/keen"
	"github.com/Bowery/gopackages/rollbar"
	"github.com/Bowery/gopackages/web"
	"github.com/orchestrate-io/gorc"
)

var (
	rollbarC    *rollbar.Client
	keenC       keen.Client
	emailClient *email.Client
	awsC        *AWSClient
	dir         string
	staticDir   string
	db          *gorc.Client
	env         string
	port        string
)

func main() {
	flag.StringVar(&env, "env", "development", "Mode to run Kepler in.")
	flag.StringVar(&port, "port", ":3000", "Port to listen on.")
	flag.Parse()

	rollbarC = rollbar.NewClient(config.RollbarToken, env)
	keenC = keen.Client{
		WriteKey:  config.KeenWriteKey,
		ProjectID: config.KeenProjectID,
	}
	emailClient = email.NewClient()
	dir, _ = filepath.Abs(filepath.Dir(os.Args[0]))
	staticDir = filepath.Join(dir, "static")
	orchestrateKey := config.OrchestrateDevKey
	if env == "production" {
		orchestrateKey = config.OrchestrateProdKey
	}
	db = gorc.NewClient(orchestrateKey)
	awsC, _ = NewAWSClient(config.S3AccessKey, config.S3SecretKey)

	server := web.NewServer(port, []web.Handler{
		new(web.SlashHandler),
		new(web.CorsHandler),
		&web.StatHandler{Key: config.StatHatKey, Name: "kenmare"},
	}, Routes)
	server.Router.NotFoundHandler = &web.NotFoundHandler{r}
	server.ListenAndServe()
}
