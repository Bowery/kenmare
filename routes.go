// Copyright 2014 Bowery, Inc.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"code.google.com/p/go-uuid/uuid"

	"github.com/Bowery/gopackages/config"
	"github.com/Bowery/gopackages/requests"
	"github.com/Bowery/gopackages/schemas"
	"github.com/Bowery/gopackages/slack"
	"github.com/gorilla/mux"
	goversion "github.com/hashicorp/go-version"
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

type CorsHandler struct {
	Handler http.Handler
}

func (ch *CorsHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Add("Access-Control-Allow-Origin", "*")
	rw.Header().Add("Access-Control-Allow-Headers", req.Header.Get("Access-Control-Request-Headers"))
	rw.Header().Add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

	if req.Method == "OPTIONS" {
		rw.WriteHeader(http.StatusOK)
		return
	}

	ch.Handler.ServeHTTP(rw, req)
}

var Routes = []*Route{
	&Route{"GET", "/", indexHandler},
	&Route{"GET", "/healthz", healthzHandler},
	&Route{"POST", "/applications", createApplicationHandler},
	&Route{"GET", "/applications", getApplicationsHandler},
	&Route{"GET", "/applications/{id}", getApplicationByIDHandler},
	&Route{"PUT", "/applications/{id}", updateApplicationByIDHandler},
	&Route{"DELETE", "/applications/{id}", removeApplicationByIDHandler},
	&Route{"GET", "/environments", searchEnvironmentsHandler},
	&Route{"GET", "/environments/{id}", getEnvironmentByIDHandler},
	&Route{"PUT", "/environments/{id}", updateEnvironmentByIDHandler},
	&Route{"POST", "/events", createEventHandler},
	&Route{"GET", "/client/check", clientCheckHandler},
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

type applicationReq struct {
	EnvID        string `json:"envID"`
	Token        string `json:"token"`
	InstanceType string `json:"instance_type"`
	AWSAccessKey string `json:"aws_access_key"`
	AWSSecretKey string `json:"aws_secret_key"`
	Ports        string `json:"ports"`
	Name         string `json:"name"`
	Start        string `json:"start"`
	Build        string `json:"build"`
	LocalPath    string `json:"localPath"`
	RemotePath   string `json:"remotePath"`
}

type Res struct {
	Status string `json:"status"`
	Err    string `json:"error"`
}

func (res *Res) Error() string {
	return res.Err
}

// createEnvironmentHandler creates a new environment
func createApplicationHandler(rw http.ResponseWriter, req *http.Request) {
	start := time.Now()
	var body applicationReq
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&body)
	if err != nil {
		rollbarC.Report(err, nil)
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	envID := body.EnvID
	token := body.Token
	instanceType := body.InstanceType
	awsAccessKey := body.AWSAccessKey
	awsSecretKey := body.AWSSecretKey
	ports := body.Ports

	// Validate request.
	if token == "" || instanceType == "" ||
		awsAccessKey == "" || awsSecretKey == "" {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  "missing fields",
		})
		return
	}

	err = validateConfig(instanceType)
	if err != nil {
		rollbarC.Report(err, map[string]interface{}{
			"body": body,
		})
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
	}

	// If an environment id is not specified, default.
	if envID == "" {
		envID = "feb1310b-2303-4265-b8a3-4d02e8f67c01"
	}

	// Fetch environment.
	sourceEnv, err := getEnv(envID)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	// Get developer via token from Broome.
	dev, err := getDev(token)
	if err != nil {
		rollbarC.Report(err, map[string]interface{}{
			"body": body,
		})
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	// Create AWS client.
	var awsClient *AWSClient
	if env != "testing" {
		awsClient, err = NewAWSClient(awsAccessKey, awsSecretKey)
		if err != nil {
			rollbarC.Report(err, map[string]interface{}{
				"body": body,
				"dev":  dev,
			})
			r.JSON(rw, http.StatusBadRequest, map[string]string{
				"status": requests.STATUS_FAILED,
				"error":  err.Error(),
			})
			return
		}
	}

	var portsList []int
	if ports != "" {
		portsSplit := strings.Split(ports, ",")
		portsList = make([]int, len(portsSplit))
		for i, port := range portsSplit {
			port = strings.Trim(port, " ")
			num, err := strconv.Atoi(port)
			if err != nil {
				rollbarC.Report(err, map[string]interface{}{
					"body": body,
					"dev":  dev,
				})
				r.JSON(rw, http.StatusBadRequest, map[string]string{
					"status": requests.STATUS_FAILED,
					"error":  fmt.Sprintf("invalid port %s", port),
				})
				return
			}

			portsList[i] = num
		}
	}

	msg := fmt.Sprintf("%s created a new application", dev.Name)
	go slack.SendMessage("#activity", msg, "Drizzy Drake")

	// Create app. This also will create a new environment.
	appID := uuid.New()
	envID = uuid.New()

	app := schemas.Application{
		ID:              appID,
		EnvID:           envID,
		DeveloperID:     dev.ID.Hex(),
		Status:          "provisioning",
		Name:            body.Name,
		Start:           body.Start,
		Build:           body.Build,
		LocalPath:       body.LocalPath,
		RemotePath:      body.RemotePath,
		CreatedAt:       time.Now(),
		IsSyncAvailable: false,
	}

	// Write to Orchestrate.
	_, err = db.Put("applications", appID, app)
	if err != nil {
		rollbarC.Report(err, map[string]interface{}{
			"body": body,
			"dev":  dev,
			"app":  app,
		})
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	// Create env. If the environment is successfully
	// created, write the events to orchestrate and
	// update the application.
	newEnv := schemas.Environment{
		ID:          envID,
		AMI:         sourceEnv.AMI,
		DeveloperID: dev.ID.Hex(),
		CreatedAt:   time.Now(),
		Count:       0,
	}
	_, err = db.Put("environments", envID, &newEnv)
	if err == nil {
		for _, e := range sourceEnv.Events {
			// todo(steve): maybe handle the error
			db.PutEvent("environments", envID, "command", e)
		}
	}
	app.Environment = newEnv

	// Create instance in background. Update the application status
	// given the results of this process.
	go func() {
		if env == "testing" {
			return
		}

		start := time.Now()

		// Get current app state since the developer may
		// have made changes since.
		currentApp, _ := getApp(app.ID)

		// Create instance.
		log.Println("creating instance")
		instanceID, err := awsClient.CreateInstance(sourceEnv.AMI, instanceType, appID, portsList)
		if err != nil {
			currentApp.Status = "error"
			appError := &schemas.Error{
				ID:        uuid.New(),
				AppID:     currentApp.ID,
				Body:      err.Error(),
				Active:    true,
				CreatedAt: time.Now(),
			}
			db.Put("applications", currentApp.ID, currentApp)
			db.PutEvent("errors", currentApp.ID, "error", appError)
		}

		elapsed := time.Since(start).Nanoseconds() / 1000000
		go keenC.AddEvent("kenmare provision instance time", map[string]interface{}{
			"duration": elapsed,
		})

		// Update application.
		currentApp.InstanceID = instanceID
		db.Put("applications", currentApp.ID, currentApp)

		// Check Instance.
		log.Println("checking instance")
		addr, err := awsClient.CheckInstance(instanceID)

		// Get current app state since the developer may
		// have made changes since.
		currentApp, _ = getApp(app.ID)

		// Check error.
		if err != nil {
			appError := &schemas.Error{
				ID:        uuid.New(),
				AppID:     currentApp.ID,
				Body:      err.Error(),
				Active:    true,
				CreatedAt: time.Now(),
			}

			currentApp.Status = "error"
			db.Put("applications", currentApp.ID, currentApp)
			db.PutEvent("errors", currentApp.ID, "error", appError)
			return
		}

		currentApp.Location = addr
		currentApp.InstanceID = instanceID

		// Wait till the agent is up and running.
		for {
			<-time.After(5 * time.Second)
			log.Println("checking agent availability")
			url := net.JoinHostPort(addr, config.BoweryAgentProdSyncPort)
			res, err := http.Get(fmt.Sprintf("http://%s", url))
			if err != nil {
				continue
			}
			if res.StatusCode == http.StatusOK {
				break
			}
		}

		// Run commands on the new instance.
		cmds := []string{}
		if err == nil {
			for _, e := range sourceEnv.Events {
				if e.Type == "command" {
					cmds = append(cmds, e.Body)
				}
			}
		}

		log.Println(fmt.Sprintf("executing %d commands", len(cmds)))
		err = DelanceyExec(currentApp, cmds)
		if err != nil {
			// todo(steve): something with this error.
			log.Println(err)
		}

		// Update app status.
		currentApp.Status = "running"
		db.Put("applications", currentApp.ID, currentApp)

		// Increment count
		sourceEnv.Count++
		db.Put("environments", sourceEnv.ID, sourceEnv)
	}()

	elapsed := time.Since(start).Nanoseconds() / 1000000
	go keenC.AddEvent("kenmare create application time", map[string]interface{}{
		"duration": elapsed,
	})

	r.JSON(rw, http.StatusOK, map[string]interface{}{
		"status":      requests.STATUS_SUCCESS,
		"application": app,
	})
}

func getApplicationsHandler(rw http.ResponseWriter, req *http.Request) {
	start := time.Now()
	token := req.FormValue("token")
	if token == "" {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  "token required",
		})
		return
	}

	dev, err := getDev(token)
	if err != nil {
		rollbarC.Report(err, map[string]interface{}{
			"token": token,
		})
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	query := fmt.Sprintf(`developerId:"%s"`, dev.ID.Hex())
	appsData, err := db.Search("applications", query, 100, 0)
	if err != nil {
		rollbarC.Report(err, map[string]interface{}{
			"dev": dev,
		})
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	apps := make([]schemas.Application, len(appsData.Results))
	for i, a := range appsData.Results {
		if err := a.Value(&apps[i]); err != nil {
			rollbarC.Report(err, map[string]interface{}{
				"dev": dev,
			})
			r.JSON(rw, http.StatusBadRequest, map[string]string{
				"status": requests.STATUS_FAILED,
				"error":  err.Error(),
			})
			return
		}
	}

	// Filter out any applications that may be owned
	// by a different developer.
	validApps := []schemas.Application{}
	for _, app := range apps {
		if app.DeveloperID == dev.ID.Hex() {
			validApps = append(validApps, app)
		}
	}

	var wg sync.WaitGroup
	wg.Add(len(validApps))

	for i, _ := range validApps {
		go func(wg *sync.WaitGroup, i int) {
			a := validApps[i]
			errors, err := getAppErrors(a.ID)
			if err == nil {
				validApps[i].Errors = errors
			}
			env, err := getEnv(a.EnvID)
			if err == nil {
				validApps[i].Environment = env
			}
			wg.Done()
		}(&wg, i)
	}

	wg.Wait()

	elapsed := time.Since(start).Nanoseconds() / 1000000
	go keenC.AddEvent("kenmare get applications time", map[string]interface{}{
		"duration": elapsed,
	})

	r.JSON(rw, http.StatusOK, map[string]interface{}{
		"status":       requests.STATUS_FOUND,
		"applications": validApps,
	})
}

func getApplicationByIDHandler(rw http.ResponseWriter, req *http.Request) {
	start := time.Now()
	vars := mux.Vars(req)
	id := vars["id"]

	if id == "c2c1b0dd-b9ff-48d6-86e6-beef1a069293" || id == "88334b51-58e7-4fa5-aab3-e817d10de44a" {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  "invalid app",
		})
		return
	}

	app, err := getApp(id)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	elapsed := time.Since(start).Nanoseconds() / 1000000
	go keenC.AddEvent("kenmare get application time", map[string]interface{}{
		"duration": elapsed,
	})

	r.JSON(rw, http.StatusOK, map[string]interface{}{
		"status":      requests.STATUS_FOUND,
		"application": app,
	})
}

func updateApplicationByIDHandler(rw http.ResponseWriter, req *http.Request) {
	start := time.Now()
	body := new(applicationReq)
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&body)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	vars := mux.Vars(req)
	id := vars["id"]
	token := body.Token

	// Validate request.
	if token == "" {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  "missing fields",
		})
		return
	}

	// Get the developer to check if authorized.
	dev, err := getDev(token)
	if err != nil {
		rollbarC.Report(err, map[string]interface{}{
			"body": body,
			"id":   id,
		})
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	// Get the application.
	appData, err := db.Get("applications", id)
	if err != nil {
		rollbarC.Report(err, map[string]interface{}{
			"body": body,
			"id":   id,
		})
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	app := new(schemas.Application)
	if err := appData.Value(app); err != nil {
		rollbarC.Report(err, map[string]interface{}{
			"body": body,
			"id":   id,
		})
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	// Check if the developer is allowed to modify the app.
	if dev.ID.Hex() != app.DeveloperID && !dev.IsAdmin {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  fmt.Sprintf("unauthorized to modify app with id %s", id),
		})
		return
	}

	// Add modifications allowed.
	if body.Name != "" {
		app.Name = body.Name
	}
	if body.Start != "" {
		app.Start = body.Start
	}
	if body.Build != "" {
		app.Build = body.Build
	}
	if body.RemotePath != "" {
		app.RemotePath = body.RemotePath
	}
	if body.LocalPath != "" {
		app.LocalPath = body.LocalPath
	}

	_, err = db.Put("applications", app.ID, app)
	if err != nil {
		rollbarC.Report(err, map[string]interface{}{
			"app": app,
			"id":  id,
		})
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	application, err := getApp(app.ID)
	if err != nil {
		rollbarC.Report(err, map[string]interface{}{
			"app": app,
			"id":  id,
		})
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	elapsed := time.Since(start).Nanoseconds() / 1000000
	go keenC.AddEvent("kenmare update application time", map[string]interface{}{
		"duration": elapsed,
	})

	r.JSON(rw, http.StatusOK, map[string]interface{}{
		"status":      requests.STATUS_SUCCESS,
		"application": application,
	})
}

func removeApplicationByIDHandler(rw http.ResponseWriter, req *http.Request) {
	start := time.Now()
	vars := mux.Vars(req)
	id := vars["id"]

	token := req.FormValue("token")
	awsAccessKey := req.FormValue("aws_access_key")
	awsSecretKey := req.FormValue("aws_secret_key")

	if token == "" {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  "token required",
		})
		return
	}

	// Get the developer to check if authorized.
	dev, err := getDev(token)
	if err != nil {
		rollbarC.Report(err, map[string]interface{}{
			"id":    id,
			"token": token,
		})
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	appData, err := db.Get("applications", id)
	if err != nil {
		rollbarC.Report(err, map[string]interface{}{
			"dev": dev,
			"id":  id,
		})
		r.JSON(rw, http.StatusOK, map[string]string{
			"status": requests.STATUS_SUCCESS,
		})
		return
	}

	app := new(schemas.Application)
	if err := appData.Value(app); err != nil {
		rollbarC.Report(err, map[string]interface{}{
			"dev": dev,
			"id":  id,
		})
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	// Check if the developer is allowed to remove the app.
	if dev.ID.Hex() != app.DeveloperID && !dev.IsAdmin {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  fmt.Sprintf("unauthorized to remove app with id %s", id),
		})
		return
	}

	// // Attempt to delete the aws instance.
	if env != "testing" && (awsAccessKey != "undefined" && awsAccessKey != "") &&
		(awsSecretKey != "undefined" && awsSecretKey != "") {
		go func() {
			// Create AWS client.
			awsClient, err := NewAWSClient(awsAccessKey, awsSecretKey)
			if err != nil {
				log.Println("can't create client")
				rollbarC.Report(err, map[string]interface{}{
					"dev": dev,
					"app": app,
				})
				return
			}

			// Remove the aws instance.
			err = awsClient.RemoveInstance(app.InstanceID)
			if err != nil {
				rollbarC.Report(err, map[string]interface{}{
					"dev": dev,
					"app": app,
				})
				return
			}
		}()
	}

	elapsed := time.Since(start).Nanoseconds() / 1000000
	go keenC.AddEvent("kenmare remove application time", map[string]interface{}{
		"duration": elapsed,
	})

	// Remove the app from the db.
	db.Delete("applications", id) // yolo(steve): wild'n'out.
	r.JSON(rw, http.StatusOK, map[string]string{
		"status": requests.STATUS_SUCCESS,
	})
}

// searchEnvironments
func searchEnvironmentsHandler(rw http.ResponseWriter, req *http.Request) {
	query := req.URL.Query().Get("query")
	if len(query) <= 0 {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  "a valid query is required",
		})
		return
	}

	envsData, err := db.Search("environments", query, 100, 0)
	if err != nil {
		rollbarC.Report(err, nil)
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	envs := make([]schemas.Environment, len(envsData.Results))
	for i, a := range envsData.Results {
		if err := a.Value(&envs[i]); err != nil {
			rollbarC.Report(err, nil)
			r.JSON(rw, http.StatusBadRequest, map[string]string{
				"status": requests.STATUS_FAILED,
				"error":  err.Error(),
			})
			return
		}
	}

	r.JSON(rw, http.StatusOK, map[string]interface{}{
		"status":       requests.STATUS_FOUND,
		"environments": envs,
	})
}

func getEnvironmentByIDHandler(rw http.ResponseWriter, req *http.Request) {
	start := time.Now()
	vars := mux.Vars(req)
	id := vars["id"]

	env, err := getEnv(id)
	if err != nil {
		rollbarC.Report(err, map[string]interface{}{
			"id": id,
		})
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
	}

	elapsed := time.Since(start).Nanoseconds() / 1000000
	go keenC.AddEvent("kenmare get environment time", map[string]interface{}{
		"duration": elapsed,
	})

	r.JSON(rw, http.StatusOK, map[string]interface{}{
		"status":      requests.STATUS_FOUND,
		"environment": env,
	})
}

type updateEnvReq struct {
	*schemas.Environment
	Token string `json:"token"`
}

func updateEnvironmentByIDHandler(rw http.ResponseWriter, req *http.Request) {
	start := time.Now()
	vars := mux.Vars(req)
	id := vars["id"]

	var body updateEnvReq
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&body)
	if err != nil {
		rollbarC.Report(err, nil)
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	// Get environment.
	env, err := getEnv(id)
	if err != nil {
		rollbarC.Report(err, map[string]interface{}{
			"id": id,
		})
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	// Get developer.
	dev, err := getDev(body.Token)
	if err != nil {
		rollbarC.Report(err, map[string]interface{}{
			"id": id,
		})
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	// Only admins and creators can edit an environment.
	if !dev.IsAdmin && dev.ID.Hex() != env.DeveloperID {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  "developer does not have permission",
		})
		return
	}

	// Only name and description can be updated.
	if env.Name != body.Name {
		env.Name = body.Name
	}
	if env.Description != body.Description {
		env.Description = body.Description
	}

	_, err = db.Put("environments", env.ID, env)
	if err != nil {
		rollbarC.Report(err, map[string]interface{}{
			"id": id,
		})
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	elapsed := time.Since(start).Nanoseconds() / 1000000
	go keenC.AddEvent("kenmare update environment time", map[string]interface{}{
		"duration": elapsed,
	})

	r.JSON(rw, http.StatusOK, map[string]interface{}{
		"status":      requests.STATUS_SUCCESS,
		"environment": env,
	})
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
		rollbarC.Report(err, nil)
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	typ := body.Type
	bdy := body.Body
	envID := body.EnvID

	if typ == "" || bdy == "" || envID == "" {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  "missing fields",
		})
		return
	}

	_, err = db.Get("environments", envID)
	if err != nil {
		rollbarC.Report(err, map[string]interface{}{
			"body": body,
		})
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	id := uuid.New()
	event := &schemas.Event{
		ID:        id,
		Type:      typ,
		Body:      bdy,
		CreatedAt: time.Now(),
	}

	err = db.PutEvent("environments", envID, typ, event)
	if err != nil {
		rollbarC.Report(err, map[string]interface{}{
			"envID": envID,
			"event": event,
		})
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	r.JSON(rw, http.StatusOK, map[string]interface{}{
		"status": requests.STATUS_SUCCESS,
		"event":  event,
	})
}

type squirrelUpdateRes struct {
	URL       string `json:"url"`
	Name      string `json:"name,omitempty"`
	Notes     string `json:"notes,omitempty"`
	Published string `json:"pub_date,omitempty"`
}

func clientCheckHandler(rw http.ResponseWriter, req *http.Request) {
	clientVersion := req.FormValue("version")
	os := req.FormValue("os")
	arch := req.FormValue("arch")
	if clientVersion == "" || os == "" || arch == "" {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Missing fields. Required fields: os, arch, and version"))
		return
	}

	// Download the current version.
	res, err := http.Get(config.ClientS3Addr + "/VERSION")
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Couldn't retrieve latest version information"))
		return
	}

	var body bytes.Buffer
	_, err = io.Copy(&body, res.Body)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}
	curVersion := strings.TrimSpace(body.String())

	// Check versions.
	var curV *goversion.Version
	clientV, err := goversion.NewVersion(clientVersion)
	if err == nil {
		curV, err = goversion.NewVersion(curVersion)
	}
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}

	// If it's the same or greater, there's no updates to do.
	if clientV.Equal(curV) || clientV.GreaterThan(curV) {
		rw.WriteHeader(http.StatusNoContent)
		return
	}

	r.JSON(rw, http.StatusOK, &squirrelUpdateRes{
		URL: fmt.Sprintf("%s/%s_%s_%s.zip", config.ClientS3Addr, curVersion, os, arch),
	})
}

// getApp retrieves an application and it's associated errors
// from Orchestrate.
func getApp(id string) (schemas.Application, error) {
	appData, err := db.Get("applications", id)
	if err != nil {
		return schemas.Application{}, err
	}

	app := schemas.Application{}
	if err := appData.Value(&app); err != nil {
		return schemas.Application{}, err
	}

	errors, err := getAppErrors(id)
	if err != nil {
		return schemas.Application{}, err
	}
	app.Errors = errors

	env, err := getEnv(app.EnvID)
	if err != nil {
		return schemas.Application{}, err
	}
	app.Environment = env

	return app, nil
}

// getAppErrors get an app's errors from Orchestrate.
func getAppErrors(id string) ([]schemas.Error, error) {
	errorsData, err := db.GetEvents("errors", id, "error")
	if err != nil {
		return []schemas.Error{}, err
	}

	var errors []schemas.Error = make([]schemas.Error, len(errorsData.Results))
	for i, e := range errorsData.Results {
		if err := e.Value(&errors[i]); err != nil {
			return []schemas.Error{}, err
		}
	}

	return errors, nil
}

// byCreatedAt implements the Sort interface for
// a slice of events.
type byCreatedAt []schemas.Event

func (v byCreatedAt) Len() int           { return len(v) }
func (v byCreatedAt) Swap(i, j int)      { v[i], v[j] = v[j], v[i] }
func (v byCreatedAt) Less(i, j int) bool { return v[i].CreatedAt.Unix() < v[j].CreatedAt.Unix() }

// getEnv retrieves an environment and it's associated events
// from Orchestrate. If an environment and events are found,
// the events are sorted in ascending order.
func getEnv(id string) (schemas.Environment, error) {
	envData, err := db.Get("environments", id)
	if err != nil {
		return schemas.Environment{}, err
	}

	env := schemas.Environment{}
	if err := envData.Value(&env); err != nil {
		return schemas.Environment{}, err
	}

	eventsData, err := db.GetEvents("environments", id, "command")
	if err != nil {
		return schemas.Environment{}, err
	}

	var events []schemas.Event = make([]schemas.Event, len(eventsData.Results))
	for i, e := range eventsData.Results {
		if err := e.Value(&events[i]); err != nil {
			return schemas.Environment{}, err
		}
	}

	env.Events = events

	// Sort events ascending.
	sort.Sort(byCreatedAt(env.Events))

	return env, nil
}

type developerRes struct {
	Status    string             `json:"status"`
	Err       string             `json:"error"`
	Developer *schemas.Developer `json:"developer"`
}

func getDev(token string) (*schemas.Developer, error) {
	addr := fmt.Sprintf("%s/developers/me?token=%s", config.BroomeAddr, token)
	res, err := http.Get(addr)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	devRes := new(developerRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(devRes)
	if err != nil {
		return nil, err
	}

	if devRes.Status == requests.STATUS_FOUND {
		return devRes.Developer, nil
	}

	return nil, errors.New(devRes.Err)
}
