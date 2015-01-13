// Copyright 2014 Bowery, Inc.

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Bowery/gopackages/aws"
	"github.com/Bowery/gopackages/config"
	"github.com/Bowery/gopackages/email"
	"github.com/Bowery/gopackages/gcloud"
	"github.com/Bowery/gopackages/rollbar"
	"github.com/Bowery/gopackages/slack"
	"github.com/Bowery/gopackages/web"
	"github.com/Bowery/gorc"
	pusherSub "github.com/oguzbilgic/pusher"
	pusherPub "github.com/timonv/pusher"
)

const (
	ImageStateStr = "imageState"
)

var (
	awsC, _     = aws.NewClient(config.S3AccessKey, config.S3SecretKey)
	gcloudC     *gcloud.Client
	rollbarC    *rollbar.Client
	pusherPubC  *pusherPub.Client
	pusherSubC  *pusherSub.Connection
	slackC      *slack.Client
	emailClient *email.Client
	dir         string
	staticDir   string
	db          *gorc.Client
	env         string
	port        string
)

func main() {
	flag.StringVar(&env, "env", "development", "Mode to run Kenmare in.")
	flag.StringVar(&port, "port", ":3000", "Port to listen on.")
	flag.Parse()

	gcloudC, _ = gcloud.NewClient(config.GoogleCloudProjectID, config.GoogleCloudEmail, []byte(config.GoogleCloudPrivateKey))
	rollbarC = rollbar.NewClient(config.RollbarToken, env)
	pusherPubC = pusherPub.NewClient(config.PusherAppID, config.PusherKey, config.PusherSecret)
	var err error
	pusherSubC, err = pusherSub.New(config.PusherKey)
	if err != nil {
		panic(err)
	}
	emailClient = email.NewClient()
	slackC = slack.NewClient(config.SlackToken)
	dir, _ = filepath.Abs(filepath.Dir(os.Args[0]))
	staticDir = filepath.Join(dir, "static")
	orchestrateKey := config.OrchestrateDevKey
	if env == "production" {
		orchestrateKey = config.OrchestrateProdKey
	}
	db = gorc.NewClient(orchestrateKey)

	fmt.Println("Firing up Kenmare in", env, "environment...")
	server := web.NewServer(port, []web.Handler{
		new(web.SlashHandler),
		new(web.CorsHandler),
		new(web.GzipHandler),
		&web.StatHandler{Key: config.StatHatKey, Name: "kenmare"},
	}, routes)
	server.AuthHandler = &web.AuthHandler{Auth: authHandler}
	server.ListenAndServe()
}
