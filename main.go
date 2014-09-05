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
	env  string
	port string
)

func main() {
	flag.StringVar(&env, "env", "development", "Mode to run Kepler in.")
	flag.StringVar(&port, "port", ":3000", "Port to listen on.")
	flag.Parse()

	orchestrateKey := config.OrchestrateDevKey
	if env == "production" {
		orchestrateKey = config.OrchestrateProdKey
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
	app.Run(port)
}
