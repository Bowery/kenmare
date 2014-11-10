// Copyright 2014 Bowery, Inc.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/mail"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"code.google.com/p/go-uuid/uuid"

	"github.com/Bowery/gopackages/config"
	"github.com/Bowery/gopackages/email"
	"github.com/Bowery/gopackages/requests"
	"github.com/Bowery/gopackages/schemas"
	"github.com/Bowery/gopackages/slack"
	"github.com/Bowery/gopackages/update"
	"github.com/Bowery/gopackages/util"
	"github.com/Bowery/gopackages/web"
	"github.com/gorilla/mux"
	"github.com/stathat/go"
	"github.com/unrolled/render"
)

var Routes = []web.Route{
	web.Route{"GET", "/", indexHandler},
	web.Route{"GET", "/healthz", healthzHandler},
	web.Route{"POST", "/applications", createApplicationHandler},
	web.Route{"GET", "/applications", getApplicationsHandler},
	web.Route{"GET", "/applications/{id}", getApplicationByIDHandler},
	web.Route{"PUT", "/applications/{id}", updateApplicationByIDHandler},
	web.Route{"DELETE", "/applications/{id}", removeApplicationByIDHandler},
	web.Route{"PUT", "/applications/{id}/save", saveApplicationByIDHandler},
	web.Route{"GET", "/environments", searchEnvironmentsHandler},
	web.Route{"GET", "/environments/{id}", getEnvironmentByIDHandler},
	web.Route{"PUT", "/environments/{id}", updateEnvironmentByIDHandler},
	web.Route{"PUT", "/environments/{id}/share", shareEnvironmentByIDHandler},
	web.Route{"DELETE", "/environments/{id}/share", revokeAcccessToEnvByIDHandler},
	web.Route{"POST", "/events", createEventHandler},
	web.Route{"GET", "/auth/validate-keys", validateKeysHandler},
	web.Route{"GET", "/client/check", clientCheckHandler},
	web.Route{"GET", "/_/stats/instance-count", getInstanceCountHandler},
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
	if token == "" || instanceType == "" {
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

	// Fetch the source environments dev.
	sourceEnvDev, err := getDevPub(token, sourceEnv.DeveloperID)
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

	hostedByBowery := false

	// Create AWS client.
	var awsClient *AWSClient
	if env != "testing" {
		// If the developer has failed to provide both keys
		// default on Bowery's keys.
		if awsAccessKey == "" || awsSecretKey == "" {
			hostedByBowery = true
			awsAccessKey = config.S3AccessKey
			awsSecretKey = config.S3SecretKey
		}

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

		valid := awsClient.ValidateKeys()
		if !valid {
			r.JSON(rw, http.StatusBadRequest, map[string]string{
				"status": requests.STATUS_FAILED,
				"error":  "invalid keys",
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
	if env != "testing" {
		go slack.SendMessage("#activity", msg, "Drizzy Drake")
	}

	// Create app. This also will create a new environment.
	appID := uuid.New()
	envID = uuid.New()

	app := schemas.Application{
		ID:              appID,
		EnvID:           envID,
		DeveloperID:     dev.ID.Hex(),
		Status:          "provisioning",
		StatusMsg:       "Creating AWS instance",
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
		IsPrivate:   sourceEnv.IsPrivate,
		AccessList:  []string{sourceEnvDev.Email},
	}

	if sourceEnv.AccessList != nil {
		for _, email := range sourceEnv.AccessList {
			if email == dev.Email || email == sourceEnvDev.Email {
				continue
			}

			newEnv.AccessList = append(newEnv.AccessList, email)
		}
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
		instanceID, err := awsClient.CreateInstance(sourceEnv.AMI, instanceType, appID, portsList, !hostedByBowery)
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

		elapsed := float64(time.Since(start).Nanoseconds() / 1000000)
		stathat.PostEZValue("kenmare provision instance time", "steve@bowery.io", elapsed)

		// Update application.
		currentApp.InstanceID = instanceID
		db.Put("applications", currentApp.ID, currentApp)

		// Check Instance.
		log.Println("checking instance")
		addr, err := awsClient.CheckInstance(instanceID)

		// Get current app state since the developer may
		// have made changes since.
		currentApp, _ = getApp(app.ID)

		currentApp.StatusMsg = "Doing health checks"
		db.Put("applications", currentApp.ID, currentApp)

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

		currentApp.StatusMsg = "Executing image commands"
		db.Put("applications", currentApp.ID, currentApp)

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

	elapsed := float64(time.Since(start).Nanoseconds() / 1000000)
	stathat.PostEZValue("kenmare create application time", "steve@bowery.io", elapsed)

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

	elapsed := float64(time.Since(start).Nanoseconds() / 1000000)
	stathat.PostEZValue("kenmare get applications time", "steve@bowery.io", elapsed)

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

	elapsed := float64(time.Since(start).Nanoseconds() / 1000000)
	stathat.PostEZValue("kenmare get application time", "steve@bowery.io", elapsed)

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

	elapsed := float64(time.Since(start).Nanoseconds() / 1000000)
	stathat.PostEZValue("kenmare update application time", "steve@bowery.io", elapsed)

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

	// Attempt to delete the aws instance.
	if env != "testing" {
		go func() {
			// Create AWS client.
			if awsAccessKey == "" || awsSecretKey == "" {
				awsAccessKey = config.S3AccessKey
				awsSecretKey = config.S3SecretKey
			}
			awsClient, err := NewAWSClient(awsAccessKey, awsSecretKey)
			if err != nil {
				log.Println("can't create client")
				rollbarC.Report(err, map[string]interface{}{
					"dev": dev,
					"app": app,
				})
				return
			}

			if app.InstanceID == "" {
				return
			}

			// Remove the aws instance. If unable to terminate the
			// instance, try again with Bowery's keys as a fallback.
			// If that doesn't work, alert user.
			err = awsClient.RemoveInstance(app.InstanceID)
			if err != nil {
				err = awsC.RemoveInstance(app.InstanceID)
				if err != nil {
					rollbarC.Report(err, map[string]interface{}{
						"dev": dev,
						"app": app,
					})

					// Notify user of error via email.
					msg, _ := email.NewEmail(
						"Unable to terminate instance",
						email.Address{
							Name:  "Bowery Support",
							Email: "support@bowery.io",
						},
						[]email.Address{
							email.Address{
								Name:  dev.Name,
								Email: dev.Email,
							},
						},
						filepath.Join(staticDir, "error-removing-instance.tmpl"),
						map[string]string{
							"Name":       strings.Split(dev.Name, " ")[0],
							"InstanceID": app.InstanceID,
						},
					)
					go emailClient.Send(msg)
					return
				}
			}
		}()
	}

	elapsed := float64(time.Since(start).Nanoseconds() / 1000000)
	stathat.PostEZValue("kenmare remove application time", "steve@bowery.io", elapsed)

	// Remove the app from the db.
	db.Delete("applications", id) // yolo(steve): wild'n'out.
	r.JSON(rw, http.StatusOK, map[string]string{
		"status": requests.STATUS_SUCCESS,
	})
}

type saveAppReq struct {
	Token        string `json:"token"`
	AWSAccessKey string `json:"aws_access_key"`
	AWSSecretKey string `json:"aws_secret_key"`
}

func saveApplicationByIDHandler(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]

	var reqBody saveAppReq
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&reqBody)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	awsAccessKey := reqBody.AWSAccessKey
	awsSecretKey := reqBody.AWSSecretKey

	app, err := getApp(id)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	if reqBody.Token == "" {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  "token required",
		})
		return
	}

	dev, err := getDev(reqBody.Token)
	if app.DeveloperID != dev.ID.Hex() {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	if reqBody.AWSAccessKey == "" || reqBody.AWSSecretKey == "" {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  "Access Key and Secret Key required",
		})
		return
	}

	// Take snapshot in background and update the
	// environment with the new AMI ID.
	go func() {
		if awsAccessKey == "" || awsSecretKey == "" {
			awsAccessKey = config.S3AccessKey
			awsSecretKey = config.S3SecretKey
		}
		awsClient, err := NewAWSClient(awsAccessKey, awsSecretKey)
		if err != nil {
			// handle error
			log.Println(err)
			return
		}

		imageID, err := awsClient.SaveInstance(app.InstanceID)
		if err != nil {
			// handle error
			log.Println(err)
			return
		}

		// Update environment.
		env, err := getEnv(app.EnvID)
		if err != nil {
			log.Println(err)
			return
		}

		env.AMI = imageID
		db.Put("environments", env.ID, env)
	}()

	r.JSON(rw, http.StatusOK, map[string]string{
		"status": requests.STATUS_SUCCESS,
	})
}

var defaultEnvs = []schemas.Environment{
	schemas.Environment{
		ID:          "2f9e2fb0-e2aa-4055-ba76-d9af93d3a547",
		Name:        "Ubuntu 14.04 LTS",
		Description: "Trusty Tahr",
		Count:       49,
		IsPrivate:   false,
	},
	schemas.Environment{
		ID:          "1fbcd81a-de9f-4a3b-8b8a-cbc2f451e8bf",
		Name:        "Node 0.10",
		Description: "Stock Ubuntu 14.04 LTS with Node 0.10, grunt-cli, nodemon and forever installed globally.",
		Count:       125,
		IsPrivate:   false,
	},
	schemas.Environment{
		ID:          "1095a390-1c99-4bd2-86d7-59633301fb4a",
		Name:        "PHP 5.5 with Composer",
		Description: "Base Ubuntu 14.04 LTS image with PHP 5.5 and composer. This supports Laravel by default.",
		Count:       15,
		IsPrivate:   false,
	},
	schemas.Environment{
		ID:          "172e5243-39f0-478a-904d-eb31cc2595a6",
		Name:        "Wordpress",
		Description: "Simple image with nginx, php-fpm, mysql and default database",
		Count:       7,
		IsPrivate:   false,
	},
	schemas.Environment{
		ID:          "b13fec32-a388-4e2c-9150-ff1dde3e0a30",
		Name:        "Drupal",
		Description: "Simple setup supporting nginx, php-fpm, defaultdb in MySQL",
		Count:       5,
		IsPrivate:   false,
	},
	schemas.Environment{
		ID:          "1df49d30-e8eb-4e15-8a5d-e136bd31c78d",
		Name:        "Joomla!",
		Description: "Preconfigured stack for Joomla! with nginx, php-fpm and mysql preconfigured",
		Count:       2,
		IsPrivate:   false,
	},
	schemas.Environment{
		ID:          "b48819c7-18b2-4772-a8fc-c0f2166ff92e",
		Name:        "Ruby 1.9.3 with Rails 4.1.6, Sqlite3",
		Description: "Base Ubuntu 14.04 LTS with Ruby, Rails and Sqlite3",
		Count:       27,
		IsPrivate:   false,
	},
	schemas.Environment{
		ID:          "38398266-ff5e-4dc4-a89f-6d7197eff4a3",
		Name:        "Orchestrate.js",
		Description: "Node.js image with Node driver for Orchestrate.io installed",
		Count:       4,
		IsPrivate:   false,
	},
}

// searchEnvironments
func searchEnvironmentsHandler(rw http.ResponseWriter, req *http.Request) {
	query := req.FormValue("query")
	if len(query) <= 0 {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  "a valid query is required",
		})
		return
	}

	// If query is default, return default environments
	// as well as any environments that the requesting
	// developer has set as private, as well as any
	// environments that have been shared with them.
	if query == "default" {
		token := req.FormValue("token")
		results := defaultEnvs
		if token != "" {
			dev, err := getDev(token)
			if err != nil {
				r.JSON(rw, http.StatusBadRequest, map[string]interface{}{
					"status": requests.STATUS_FAILED,
					"error":  err.Error(),
				})
				return
			}
			query := fmt.Sprintf("(value.isPrivate:true AND developerID:%s) OR value.accessList:\"%s\"",
				dev.ID.Hex(), dev.Email)
			envs, err := searchEnvs(query)
			if err != nil {
				r.JSON(rw, http.StatusBadRequest, map[string]interface{}{
					"status": requests.STATUS_FAILED,
					"error":  err.Error(),
				})
				return
			}

			for _, e := range envs {
				results = append(results, e)
			}
		}
		r.JSON(rw, http.StatusOK, map[string]interface{}{
			"status":       requests.STATUS_FOUND,
			"environments": results,
		})
		return
	}

	// If the query is non-default, run a basic search.
	envs, err := searchEnvs(query)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]interface{}{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
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

	elapsed := float64(time.Since(start).Nanoseconds() / 1000000)
	stathat.PostEZValue("kenmare get environment time", "steve@bowery.io", elapsed)

	r.JSON(rw, http.StatusOK, map[string]interface{}{
		"status":      requests.STATUS_FOUND,
		"environment": env,
	})
}

type updateEnvReq struct {
	*schemas.Environment
	Token        string `json:"token"`
	AWSAccessKey string `json:"aws_access_key"`
	AWSSecretKey string `json:"aws_secret_key"`
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
	environment, err := getEnv(id)
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
	if !dev.IsAdmin && dev.ID.Hex() != environment.DeveloperID {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  "developer does not have permission",
		})
		return
	}

	// Only name, description, privacy, and accessList can be updated.
	if environment.Name != body.Name {
		environment.Name = body.Name
	}
	if environment.Description != body.Description {
		environment.Description = body.Description
	}
	if environment.IsPrivate != body.IsPrivate {
		environment.IsPrivate = body.IsPrivate
	}
	if !reflect.DeepEqual(environment.AccessList, body.AccessList) {
		for _, d := range body.AccessList {
			if !util.StringInSlice(environment.AccessList, d) {
				go shareEnv(&environment, dev, d)
			}
		}

		environment.AccessList = body.AccessList
	}

	_, err = db.Put("environments", environment.ID, environment)
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

	elapsed := float64(time.Since(start).Nanoseconds() / 1000000)
	stathat.PostEZValue("kenmare update environment time", "steve@bowery.io", elapsed)

	r.JSON(rw, http.StatusOK, map[string]interface{}{
		"status":      requests.STATUS_SUCCESS,
		"environment": environment,
	})
}

type shareEnvReq struct {
	Token string `json:"token"`
	Email string `json:"email"`
}

// shareEnvironmentByIDHandler gives a developer the necessary permissions
// to access an environment. The developer will be sent an email making
// them aware of the shared image, and prompt them to create an account
// if there is not one already.
func shareEnvironmentByIDHandler(rw http.ResponseWriter, req *http.Request) {
	start := time.Now()
	vars := mux.Vars(req)
	envID := vars["id"]

	var body shareEnvReq
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&body)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	// validate environment.
	environment, err := getEnv(envID)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  "no such environment exists",
		})
		return
	}

	// validate developer.
	dev, err := getDev(body.Token)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  "no such developer exists",
		})
		return
	}

	err = shareEnv(&environment, dev, body.Email)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	// update permissions.
	environment.AccessList = util.AppendUniqueStr(environment.AccessList, body.Email)
	_, err = db.Put("environments", environment.ID, environment)
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	elapsed := float64(time.Since(start).Nanoseconds() / 1000000)
	stathat.PostEZValue("kenmare share environment time", "steve@bowery.io", elapsed)

	r.JSON(rw, http.StatusOK, map[string]interface{}{
		"status":      requests.STATUS_SUCCESS,
		"environment": environment,
	})
}

func revokeAcccessToEnvByIDHandler(rw http.ResponseWriter, req *http.Request) {
	// todo(steve).
	r.JSON(rw, http.StatusOK, map[string]string{
		"status": requests.STATUS_SUCCESS,
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

func validateKeysHandler(rw http.ResponseWriter, req *http.Request) {
	awsAccessKey := req.URL.Query().Get("aws_access_key")
	awsSecretKey := req.URL.Query().Get("aws_secret_key")

	if awsAccessKey == "" || awsSecretKey == "" {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  "Access Key and Secret Key required",
		})
		return
	}

	var awsClient *AWSClient
	var err error
	if env != "testing" {
		awsClient, err = NewAWSClient(awsAccessKey, awsSecretKey)
		if err != nil {
			r.JSON(rw, http.StatusBadRequest, map[string]string{
				"status": requests.STATUS_FAILED,
				"error":  err.Error(),
			})
			return
		}
	}

	valid := awsClient.ValidateKeys()
	if !valid {
		r.JSON(rw, http.StatusOK, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  "invalid keys",
		})
		return
	}

	r.JSON(rw, http.StatusOK, map[string]string{
		"status": requests.STATUS_SUCCESS,
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

	curVersion, curVerURL, err := update.GetLatest(config.ClientS3Addr + "/VERSION")
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}

	changed, err := update.OutOfDate(clientVersion, curVersion)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}

	if !changed {
		rw.WriteHeader(http.StatusNoContent)
		return
	}

	r.JSON(rw, http.StatusOK, &squirrelUpdateRes{
		URL:  curVerURL,
		Name: "Bowery " + curVersion,
	})
}

func getInstanceCountHandler(rw http.ResponseWriter, req *http.Request) {
	count, err := awsC.GetInstanceCount()
	if err != nil {
		r.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.STATUS_FAILED,
			"error":  err.Error(),
		})
		return
	}

	r.JSON(rw, http.StatusOK, map[string]interface{}{
		"item": []interface{}{
			map[string]interface{}{
				"value": count,
				"text":  "Instance Count",
			},
		},
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

func searchEnvs(query string) ([]schemas.Environment, error) {
	envsData, err := db.Search("environments", query, 100, 0)
	if err != nil {
		return []schemas.Environment{}, err
	}

	envs := make([]schemas.Environment, len(envsData.Results))
	for i, a := range envsData.Results {
		if err := a.Value(&envs[i]); err != nil {
			return []schemas.Environment{}, err
		}
	}

	return envs, nil
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

func getDevPub(token, id string) (*schemas.Developer, error) {
	addr := fmt.Sprintf("%s/developers/%s?token=%s", config.BroomeAddr, id, token)
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

func shareEnv(environment *schemas.Environment, developer *schemas.Developer, emailAddr string) error {
	// ensure proper access.
	if environment.DeveloperID != developer.ID.Hex() {
		return errors.New("invalid permissions")
	}

	_, err := mail.ParseAddress(emailAddr)
	if err != nil {
		return errors.New("invalid email")
	}

	// send email to user.
	if env != "testing" {
		go func() {
			msg, _ := email.NewEmail(
				fmt.Sprintf("[test] %s wants to share an environment with you", developer.Name),
				email.Address{
					Name:  "Bowery",
					Email: "support@bowery.io",
				},
				[]email.Address{
					email.Address{
						Email: emailAddr,
					},
				},
				filepath.Join(staticDir, "share-environment.tmpl"),
				map[string]string{
					"FriendName": strings.Split(developer.Name, " ")[0],
					"EnvName":    environment.Name,
					"EnvDesc":    environment.Description,
				},
			)

			emailClient.Send(msg)
			return
		}()
	}

	return nil
}
