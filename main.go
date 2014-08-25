// Copyright 2014 Bowery, Inc.
package main

import (
	"flag"

	"github.com/Bowery/gopackages/config"
	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
	"github.com/orchestrate-io/gorc"
)

var (
	db   *gorc.Client
	env  = flag.String("env", "development", "Mode to run Kepler in.")
	port = flag.String("port", ":3000", "Port to listen on.")
)

func main() {
	flag.Parse()

	orchestrateKey := config.OrchestrateDevKey
	if *env == "production" {
		orchestrateKey = config.OrchestrateProdKey
		*port = ":80"
	}
	db = gorc.NewClient(orchestrateKey)

	router := mux.NewRouter()
	for _, r := range Routes {
		route := router.NewRoute()
		route.Path(r.Path).Methods(r.Method)
		route.HandlerFunc(r.Handler)
	}

	app := negroni.Classic()
	app.UseHandler(&SlashHandler{router})
	app.Run(*port)
}
