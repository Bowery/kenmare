// Copyright 2014 Bowery, Inc.
package main

import (
	"fmt"
	"net/http"
	"strings"

	"code.google.com/p/go-uuid/uuid"

	"github.com/gorilla/mux"
	"github.com/unrolled/render"
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
	&Route{"POST", "/environments", createNewEnvironmentHandler},
	&Route{"GET", "/environments/{id}", getEnvironmentByID},
}

var r = render.New(render.Options{
	IndentJSON:    true,
	IsDevelopment: true,
})

func indexHandler(rw http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(rw, "Bowery Environment Manager")
}

func healthzHandler(rw http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(rw, "ok")
}

func createNewEnvironmentHandler(rw http.ResponseWriter, req *http.Request) {
	ami := req.FormValue("ami")
	instanceType := req.FormValue("instance_type")
	awsAccessKey := req.FormValue("aws_access_key")
	awsSecretKey := req.FormValue("aws_secret_key")

	if ami == "" || instanceType == "" || awsAccessKey == "" || awsSecretKey == "" {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": "missing fields",
		})
		return
	}

	// todo(steve): enable this.
	// awsClient := NewAWSClient(awsAccessKey, awsSecretKey)
	// addr, err := awsClient.CreateInstance(ami, instanceType)
	// if err != nil {
	// 	r.JSON(rw, http.StatusBadRequest, map[string]string{
	// 		"error": err.Error(),
	// 	})
	// 	return
	// }

	id := uuid.New()
	env := &Environment{
		ID:           id,
		AMI:          ami,
		InstanceType: instanceType,
	}

	_, err := db.Put("environments", id, env)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	r.JSON(rw, http.StatusOK, env)
}

func getEnvironmentByID(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]

	data, err := db.Get("environments", id)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	env := Environment{}
	if err := data.Value(&env); err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	r.JSON(rw, http.StatusBadRequest, env)
}
