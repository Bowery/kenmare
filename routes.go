// Copyright 2014 Bowery, Inc.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"code.google.com/p/go-uuid/uuid"

	"github.com/Bowery/gopackages/schemas"
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
	&Route{"POST", "/applications", createApplicationHandler},
	&Route{"GET", "/applications/{id}", getApplicationByID},
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

type createEnvironmentReq struct {
	AMI          string `json:"ami"`
	EnvID        string `json:"envID"`
	InstanceType string `json:"instance_type"`
	AWSAccessKey string `json:"aws_access_key"`
	AWSSecretKey string `json:"aws_secret_key"`
	Ports        string `json:"ports"`
}

// createEnvironmentHandler creates a new environment
func createApplicationHandler(rw http.ResponseWriter, req *http.Request) {
	var body createEnvironmentReq
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&body)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	ami := body.AMI
	instanceType := body.InstanceType
	awsAccessKey := body.AWSAccessKey
	awsSecretKey := body.AWSSecretKey
	ports := body.Ports

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

	var portsList []int
	if ports != "" {
		portsSplit := strings.Split(ports, ",")
		portsList = make([]int, len(portsSplit))
		for i, port := range portsSplit {
			port = strings.Trim(port, " ")
			num, err := strconv.Atoi(port)
			if err != nil {
				r.JSON(rw, http.StatusBadRequest, map[string]string{
					"error": fmt.Sprintf("invalid port %s", port),
				})
				return
			}

			portsList[i] = num
		}
	}

	// Create app
	appID := uuid.New()
	envID := uuid.New()

	app := schemas.Application{
		ID:     appID,
		EnvID:  envID,
		Status: "provisioning",
	}

	_, err = db.Put("applications", appID, app)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	// Create instance in background. Update the application status
	// given the results of this process.
	go func() {
		addr, err := awsClient.CreateInstance(ami, instanceType, appID, portsList)
		if err != nil {
			app.Status = "failed"
			db.Put("applications", app.ID, app)
			return
		}

		env := &schemas.Environment{
			ID:           envID,
			AMI:          ami,
			InstanceType: instanceType,
		}

		// Create env. If the environment is successfully
		// created, update the application.
		_, err = db.Put("environments", envID, env)
		if err == nil {
			app.Location = addr
			app.Status = "running"
			db.Put("applications", app.ID, app)
		}
	}()

	r.JSON(rw, http.StatusOK, map[string]interface{}{
		"status": "pending",
		"appID":  appID,
	})
}

func getApplicationByID(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]

	appData, err := db.Get("applications", id)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	app := schemas.Application{}
	if err := appData.Value(&app); err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	r.JSON(rw, http.StatusOK, app)
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

	env := schemas.Environment{}
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

	var events []schemas.Event = make([]schemas.Event, len(eventsData.Results))
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

type createEventReq struct {
	Type  string `json:"type"`
	Body  string `json:"body"`
	EnvID string `json:"envID"`
}

func createEventHandler(rw http.ResponseWriter, req *http.Request) {
	var body createEventReq
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&body)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	typ := body.Type
	bdy := body.Body
	envID := body.EnvID

	if typ == "" || bdy == "" || envID == "" {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": "missing fields",
		})
		return
	}

	_, err = db.Get("environments", envID)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	id := uuid.New()
	event := &schemas.Event{
		ID:   id,
		Type: typ,
		Body: bdy,
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
