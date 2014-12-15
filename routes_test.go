package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"log"

	"labix.org/v2/mgo/bson"

	"github.com/Bowery/gopackages/config"
	"github.com/Bowery/gopackages/requests"
	"github.com/Bowery/gopackages/rollbar"
	"github.com/Bowery/gopackages/schemas"
	"github.com/gorilla/mux"
	"github.com/orchestrate-io/gorc"
)

type createApplicationRes struct {
	Status      string               `json:"status"`
	Err         string               `json:"error"`
	Application *schemas.Application `json:"application"`
}

type getApplicationsRes struct {
	Status       string                 `json:"status"`
	Err          string                 `json:"error"`
	Applications []*schemas.Application `json:"applications"`
}

type applicationRes struct {
	Status      string               `json:"status"`
	Err         string               `json:"error"`
	Application *schemas.Application `json:"application"`
}

type environmentRes struct {
	Status      string               `json:"status"`
	Err         string               `json:"error"`
	Environment *schemas.Environment `json:"environment"`
}

var devs = map[string]*schemas.Developer{
	"admin": {
		ID:      bson.NewObjectId(),
		Email:   "admin@bowery.io",
		Name:    "admin",
		Token:   "admin",
		IsAdmin: true,
	},
	"noapps": {
		ID:    bson.NewObjectId(),
		Email: "noapps@bowery.io",
		Name:  "noapps",
		Token: "noapps",
	},
	"apps": {
		ID:    bson.NewObjectId(),
		Email: "apps@bowery.io",
		Name:  "apps",
		Token: "apps",
	},
}

var (
	createdApp       *schemas.Application
	createdContainer *schemas.Container
)

func init() {
	rollbarC = rollbar.NewClient("", "testing")
	db = gorc.NewClient(config.OrchestrateDevKey)
	env = "testing" // Disables the aws features.
}

func createApplicationMock(addr string) (*createApplicationRes, error) {
	appReq := &applicationReq{
		EnvID:        "2336c5ae-f03a-405f-b48c-d46540ab8702",
		Token:        devs["apps"].Token,
		InstanceType: "m3.medium",
		AWSAccessKey: "access",
		AWSSecretKey: "secret",
		Ports:        "22,80,4000",
	}

	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	err := encoder.Encode(appReq)
	if err != nil {
		return nil, err
	}

	res, err := http.Post(addr+"/applications", "application/json", &body)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	resp := new(createApplicationRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func TestCreateApplication(t *testing.T) {
	server := startServer()
	defer server.Close()
	defer startBroome().Close()

	resp, err := createApplicationMock(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status == requests.StatusFailed {
		t.Error("Reponse failed but should have succeeded ", resp.Err)
	} else {
		if resp.Application.DeveloperID != devs["apps"].ID.Hex() {
			t.Error("Applications developer id doesn't match the token given")
		}
		createdApp = resp.Application
	}
}

func TestCreateApplicationMissing(t *testing.T) {
	server := startServer()
	defer server.Close()
	defer startBroome().Close()

	appReq := &applicationReq{
		EnvID: "2336c5ae-f03a-405f-b48c-d46540ab8702",
		Token: devs["apps"].Token,
		Ports: "22,80,4000",
	}

	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	err := encoder.Encode(appReq)
	if err != nil {
		t.Fatal(err)
	}

	res, err := http.Post(server.URL+"/applications", "application/json", &body)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	resp := new(createApplicationRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status != requests.StatusFailed {
		t.Error("Reponse succeeded but should have failed")
	}
}

func TestCreateApplicationBadToken(t *testing.T) {
	server := startServer()
	defer server.Close()
	defer startBroome().Close()

	appReq := &applicationReq{
		EnvID:        "2336c5ae-f03a-405f-b48c-d46540ab8702",
		Token:        "badtoken",
		InstanceType: "m3.medium",
		AWSAccessKey: "access",
		AWSSecretKey: "secret",
		Ports:        "22,80,4000",
	}

	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	err := encoder.Encode(appReq)
	if err != nil {
		t.Fatal(err)
	}

	res, err := http.Post(server.URL+"/applications", "application/json", &body)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	resp := new(createApplicationRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status != requests.StatusFailed {
		t.Error("Reponse succeeded but should have failed")
	}
}

func TestGetApplications(t *testing.T) {
	if createdApp == nil {
		t.Skip("Skipping because create failed")
	}
	<-time.After(time.Second) // Searching takes a sec to work properly.
	server := startServer()
	defer server.Close()
	defer startBroome().Close()

	res, err := http.Get(server.URL + "/applications?token=" + devs["apps"].Token)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	resp := new(getApplicationsRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status == requests.StatusFailed {
		t.Error("Reponse failed but should have succeeded ", resp.Err)
	} else {
		if len(resp.Applications) < 1 {
			t.Error("Should have at least one application")
		} else {
			var found *schemas.Application
			for _, app := range resp.Applications {
				if createdApp != nil && app.ID == createdApp.ID {
					found = app
				}
			}

			if found == nil {
				t.Error("The application created earlier isn't included")
			}
		}
	}
}

func TestGetApplicationsNoToken(t *testing.T) {
	server := startServer()
	defer server.Close()
	defer startBroome().Close()

	res, err := http.Get(server.URL + "/applications")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	resp := new(getApplicationsRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status != requests.StatusFailed {
		t.Error("Response succeeded but should have failed")
	}
}

func TestGetApplicationsBadToken(t *testing.T) {
	server := startServer()
	defer server.Close()
	defer startBroome().Close()

	res, err := http.Get(server.URL + "/applications?token=badtoken")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	resp := new(getApplicationsRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status != requests.StatusFailed {
		t.Error("Response succeeded but should have failed")
	}
}

func TestGetApplication(t *testing.T) {
	if createdApp == nil {
		t.Skip("Skipping because create failed")
	}
	server := startServer()
	defer server.Close()

	res, err := http.Get(server.URL + "/applications/" + createdApp.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	resp := new(applicationRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status == requests.StatusFailed {
		t.Error("Response failed but should have succeeded ", resp.Err)
	} else {
		if resp.Application.Name != createdApp.Name {
			t.Error("Applications name doesn't match the created one")
		}
	}
}

func TestGetApplicationBadID(t *testing.T) {
	server := startServer()
	defer server.Close()

	res, err := http.Get(server.URL + "/applications/randomid")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	resp := new(applicationRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status != requests.StatusFailed {
		t.Error("Response succeeded but should have failed")
	}
}

func TestUpdateApplication(t *testing.T) {
	if createdApp == nil {
		t.Skip("Skipping because create failed")
	}
	server := startServer()
	defer server.Close()
	defer startBroome().Close()

	appReq := &applicationReq{
		Token: devs["apps"].Token,
		Name:  "newnamehere",
	}

	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	err := encoder.Encode(appReq)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("PUT", server.URL+"/applications/"+createdApp.ID, &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	resp := new(applicationRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status == requests.StatusFailed {
		t.Error("Reponse failed but should have succeeded ", resp.Err)
	} else {
		if resp.Application.Name == createdApp.Name {
			t.Error("Application name should have changed but didn't")
		}
		createdApp = resp.Application
	}
}

func TestUpdateApplicationNoToken(t *testing.T) {
	server := startServer()
	defer server.Close()
	defer startBroome().Close()

	appReq := &applicationReq{
		Name: "newnamehere",
	}

	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	err := encoder.Encode(appReq)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("PUT", server.URL+"/applications/"+createdApp.ID, &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	resp := new(applicationRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status != requests.StatusFailed {
		t.Error("Reponse succeeded but should have failed")
	}
}

func TestUpdateApplicationBadToken(t *testing.T) {
	server := startServer()
	defer server.Close()
	defer startBroome().Close()

	appReq := &applicationReq{
		Token: "sometoken",
		Name:  "newnamehere",
	}

	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	err := encoder.Encode(appReq)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("PUT", server.URL+"/applications/"+createdApp.ID, &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	resp := new(applicationRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status != requests.StatusFailed {
		t.Error("Reponse succeeded but should have failed")
	}
}

func TestUpdateApplicationBadID(t *testing.T) {
	server := startServer()
	defer server.Close()
	defer startBroome().Close()

	appReq := &applicationReq{
		Token: devs["apps"].Token,
		Name:  "newnamehere",
	}

	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	err := encoder.Encode(appReq)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("PUT", server.URL+"/applications/randomid", &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	resp := new(applicationRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status != requests.StatusFailed {
		t.Error("Reponse succeeded but should have failed")
	}
}

func TestUpdateApplicationUnauthorized(t *testing.T) {
	server := startServer()
	defer server.Close()
	defer startBroome().Close()

	appReq := &applicationReq{
		Token: devs["noapps"].Token,
		Name:  "newnamehere",
	}

	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	err := encoder.Encode(appReq)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("PUT", server.URL+"/applications/"+createdApp.ID, &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	resp := new(applicationRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status != requests.StatusFailed {
		t.Error("Reponse succeeded but should have failed")
	}
}

func TestUpdateApplicationAdmin(t *testing.T) {
	server := startServer()
	defer server.Close()
	defer startBroome().Close()

	appReq := &applicationReq{
		Token: devs["admin"].Token,
		Name:  "anothernamehere",
	}

	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	err := encoder.Encode(appReq)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("PUT", server.URL+"/applications/"+createdApp.ID, &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	resp := new(applicationRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status == requests.StatusFailed {
		t.Error("Reponse failed but should have succeeded ", resp.Err)
	} else {
		if resp.Application.Name == createdApp.Name {
			t.Error("Application name should have changed but didn't")
		}
		createdApp = resp.Application
	}
}

func TestRemoveApplication(t *testing.T) {
	if createdApp == nil {
		t.Skip("Skipping because create failed")
	}
	server := startServer()
	defer server.Close()
	defer startBroome().Close()

	query := "?aws_access_key=someaccess&aws_secret_key=somesecret&token=" + devs["apps"].Token
	req, err := http.NewRequest("DELETE", server.URL+"/applications/"+createdApp.ID+query, nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	resp := new(applicationRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status == requests.StatusFailed {
		t.Error("Reponse failed but should have succeeded ", resp.Err)
	}
}

func TestRemoveApplicationMissing(t *testing.T) {
	server := startServer()
	defer server.Close()
	defer startBroome().Close()

	req, err := http.NewRequest("DELETE", server.URL+"/applications/"+createdApp.ID, nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	resp := new(applicationRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status != requests.StatusFailed {
		t.Error("Reponse succeeded but should have failed")
	}
}

func TestRemoveApplicationBadToken(t *testing.T) {
	server := startServer()
	defer server.Close()
	defer startBroome().Close()

	query := "?aws_access_key=someaccess&aws_secret_key=somesecret&token=sometoken"
	req, err := http.NewRequest("DELETE", server.URL+"/applications/"+createdApp.ID+query, nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	resp := new(applicationRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status != requests.StatusFailed {
		t.Error("Reponse succeeded but should have failed")
	}
}

func TestRemoveApplicationAdmin(t *testing.T) {
	server := startServer()
	defer server.Close()
	defer startBroome().Close()

	createResp, err := createApplicationMock(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	if createResp.Status == requests.StatusFailed {
		t.Fatal(createResp.Err)
	} else {
		createdApp = createResp.Application
	}

	query := "?aws_access_key=someaccess&aws_secret_key=somesecret&token=" + devs["admin"].Token
	req, err := http.NewRequest("DELETE", server.URL+"/applications/"+createdApp.ID+query, nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	resp := new(applicationRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status == requests.StatusFailed {
		t.Error("Reponse failed but should have succeeded ", resp.Err)
	}
}

func TestGetEnvironmentBadID(t *testing.T) {
	server := startServer()
	defer server.Close()

	res, err := http.Get(server.URL + "/environments/randomid")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	resp := new(environmentRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status != requests.StatusFailed {
		t.Error("Reponse succeeded but should have failed")
	}
}

func TestShareEnvironmentSuccessful(t *testing.T) {
	env, err := testShareEnv(createdApp.EnvID, devs["apps"].Token, "j-money@bowery.io")
	if err != nil {
		t.Error("Response failed but should hav succeeded", err)
	}

	devWasAdded := false
	for _, dev := range env.AccessList {
		if dev == "j-money@bowery.io" {
			devWasAdded = true
			break
		}
	}

	if !devWasAdded {
		t.Error("developer was not added to access list")
	}
}

func TestShareEnvironmentBadEnvID(t *testing.T) {
	_, err := testShareEnv("bad-env-id", devs["apps"].Token, "j-money@bowery.io")
	if err != nil && err.Error() != "no such environment exists" {
		t.Error("Response failed unexpectedly", err)
	}
}

func TestShareEnvironmentBadToken(t *testing.T) {
	_, err := testShareEnv(createdApp.EnvID, "bad-token", "j-money@bowery.io")
	if err != nil && err.Error() != "no such developer exists" {
		t.Error("Response failed unexpectedly", err)
	}
}

func TestShareEnvironmentBadEmail(t *testing.T) {
	_, err := testShareEnv(createdApp.EnvID, devs["apps"].Token, "bad-email")
	if err != nil && err.Error() != "invalid email" {
		t.Error("Response failed unexpectedly", err)
	}
}

func testShareEnv(envID, token, email string) (*schemas.Environment, error) {
	server := startServer()
	defer server.Close()
	defer startBroome().Close()

	shareReq := &shareEnvReq{
		Token: token,
		Email: email,
	}

	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	err := encoder.Encode(shareReq)
	if err != nil {
		return nil, err
	}

	addr := fmt.Sprintf("%s/environments/%s/share?token=%s", server.URL, envID, token)
	req, err := http.NewRequest("PUT", addr, &body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	resp := new(environmentRes)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(resp)
	if err != nil {
		return nil, err
	}

	if resp.Status != requests.StatusSuccess {
		return nil, errors.New(resp.Err)
	}

	return resp.Environment, nil
}

func TestCreateContainerSuccessful(t *testing.T) {
	server := startServer()
	defer server.Close()

	containerReq := &requests.ContainerReq{
		ImageID: "some-image-id",
	}

	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	err := encoder.Encode(containerReq)
	if err != nil {
		t.Error(err)
	}

	addr := fmt.Sprintf("%s/containers", server.URL)
	res, err := http.Post(addr, "application/json", &body)
	if err != nil {
		t.Error(err)
	}
	defer res.Body.Close()

	var resBody requests.ContainerRes
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resBody)
	if err != nil {
		t.Error(err)
	}

	if resBody.Status != requests.StatusCreated {
		t.Error("unexpected status returned", resBody.Status)
	}

	createdContainer = resBody.Container
}

func TestGetContainerSuccessful(t *testing.T) {
	if createdContainer == nil {
		t.Skip("Skipping because create failed")
	}

	server := startServer()
	defer server.Close()

	addr := fmt.Sprintf("%s/containers/%s", server.URL, createdContainer.ID)
	log.Println(addr)
	res, err := http.Get(addr)
	if err != nil {
		t.Error(err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Error("unexpected status returned", res.StatusCode)
	}
}

func TestRemoveContainerSuccessful(t *testing.T) {
	if createdContainer == nil {
		t.Skip("Skipping because create failed")
	}

	server := startServer()
	defer server.Close()

	addr := fmt.Sprintf("%s/containers/%s", server.URL, createdContainer.ID)
	req, err := http.NewRequest("DELETE", addr, nil)
	if err != nil {
		t.Error(err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Error("unexpected status returned", res.StatusCode)
	}
}

func TestRemoveContainerBadRequest(t *testing.T) {
	server := startServer()
	defer server.Close()

	addr := fmt.Sprintf("%s/containers/%s", server.URL, "random-id")
	req, err := http.NewRequest("DELETE", addr, nil)
	if err != nil {
		t.Error(err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusBadRequest {
		t.Error("unexpected status returned", res.StatusCode)
	}
}

// Start a server passing the request through mux for route processing.
func startServer() *httptest.Server {
	router := mux.NewRouter()
	for _, r := range routes {
		route := router.NewRoute()
		route.Path(r.Path).Methods(r.Method)
		route.HandlerFunc(r.Handler)
	}

	return httptest.NewServer(router)
}

// Start a mock broom server and set the broome address to it.
func startBroome() *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(broomeHandler))
	config.BroomeAddr = server.URL

	return server
}

// Retrieve developers from the devs map.
func broomeHandler(rw http.ResponseWriter, req *http.Request) {
	token := req.FormValue("token")
	if token == "" {
		renderer.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.StatusFailed,
			"error":  "token required",
		})
		return
	}

	dev, ok := devs[token]
	if ok {
		renderer.JSON(rw, http.StatusOK, map[string]interface{}{
			"status":    requests.StatusFound,
			"developer": dev,
		})
		return
	}

	renderer.JSON(rw, http.StatusBadRequest, map[string]string{
		"status": requests.StatusFailed,
		"error":  "invalid token",
	})
}
