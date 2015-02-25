// Copyright 2014 Bowery, Inc.

package main

import (
	"flag"
	"fmt"

	"github.com/Bowery/gopackages/aws"
	"github.com/Bowery/gopackages/config"
	"github.com/Bowery/gopackages/etcdb"
	"github.com/Bowery/gopackages/gcloud"
	"github.com/Bowery/gopackages/web"
	"github.com/timonv/pusher"
)

var (
	awsC, _ = aws.NewClient(config.S3AccessKey, config.S3SecretKey)
	gcloudC *gcloud.Client
	pusherC *pusher.Client
	db      *etcdb.Client
	env     string
	port    string
)

func main() {
	flag.StringVar(&env, "env", "development", "Mode to run Kenmare in.")
	flag.StringVar(&port, "port", ":3000", "Port to listen on.")
	flag.Parse()

	gcloudC, _ = gcloud.NewClient(config.GoogleCloudProjectID, config.GoogleCloudEmail, []byte(config.GoogleCloudPrivateKey))
	pusherC = pusher.NewClient(config.PusherAppID, config.PusherKey, config.PusherSecret)
	db = etcdb.New([]string{"http://localhost:4001"})

	fmt.Println("Firing up Kenmare in", env, "environment...")
	server := web.NewServer(port, []web.Handler{
		new(web.SlashHandler),
		new(web.CorsHandler),
		new(web.GzipHandler),
	}, routes)
	server.AuthHandler = &web.AuthHandler{Auth: web.DefaultAuthHandler}
	server.ListenAndServe()
}
