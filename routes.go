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
	&Route{"POST", "/environments", createEnvironmentHandler},
	&Route{"GET", "/environments/{id}", getEnvironmentByID},
	&Route{"POST", "/events", createEventHandler},
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

func createEnvironmentHandler(rw http.ResponseWriter, req *http.Request) {
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

	awsClient, err := NewAWSClient(awsAccessKey, awsSecretKey)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	addr, err := awsClient.CreateInstance(ami, instanceType)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	id := uuid.New()
	env := &Environment{
		ID:           id,
		AMI:          ami,
		InstanceType: instanceType,
	}

	_, err = db.Put("environments", id, env)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	r.JSON(rw, http.StatusOK, map[string]interface{}{
		"status":      "created",
		"environment": env,
		"address":     addr,
	})
}

func getEnvironmentByID(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]

	envData, err := db.Get("environments", id)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	env := Environment{}
	if err := envData.Value(&env); err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	eventsData, err := db.GetEvents("events", id, "event")
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	var events []Event = make([]Event, len(eventsData.Results))
	for i, e := range eventsData.Results {
		if err := e.Value(&events[i]); err != nil {
			r.JSON(rw, http.StatusBadRequest, map[string]string{
				"error": err.Error(),
			})
			return
		}
	}

	env.Events = events
	r.JSON(rw, http.StatusBadRequest, env)
}

func createEventHandler(rw http.ResponseWriter, req *http.Request) {
	typ := req.FormValue("type")
	body := req.FormValue("body")
	envID := req.FormValue("envID")

	if typ == "" || body == "" || envID == "" {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": "missing fields",
		})
		return
	}

	_, err := db.Get("environments", envID)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	id := uuid.New()
	event := &Event{
		ID:   id,
		Type: typ,
		Body: body,
	}

	err = db.PutEvent("events", envID, "event", event)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	r.JSON(rw, http.StatusOK, event)
}
