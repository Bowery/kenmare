// Copyright 2014 Bowery, Inc.
package main

import (
	"fmt"
	"net/http"
	"strings"
)

type Route struct {
	Method  string
	Path    string
	Handler http.HandlerFunc
}

type SlashHandler struct {
	Handler http.Handler
}

func (sh *SlashHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		req.URL.Path = strings.TrimRight(req.URL.Path, "/")
		req.RequestURI = req.URL.RequestURI()
	}

	sh.Handler.ServeHTTP(rw, req)
}

var Routes = []*Route{
	&Route{"GET", "/", indexHandler},
	&Route{"GET", "/healthz", healthzHandler},
}

func indexHandler(rw http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(rw, "Bowery Environment Manager")
}

func healthzHandler(rw http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(rw, "ok")
}
