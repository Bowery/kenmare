package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"code.google.com/p/go-uuid/uuid"
	"github.com/Bowery/gopackages/etcdb"
	"github.com/Bowery/gopackages/requests"
	"github.com/Bowery/gopackages/schemas"
	"github.com/gorilla/mux"
)

var (
	testImageID      = uuid.New()
	testProject      *schemas.Project
	createdContainer *schemas.Container
)

func init() {
	db = etcdb.New([]string{"http://localhost:4001"})
	env = "testing"
}

func TestCreateContainerSuccessful(t *testing.T) {
	server := startServer()
	defer server.Close()

	containerReq := &requests.ContainerReq{
		ImageID: testImageID,
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
	res, err := http.Get(addr)
	if err != nil {
		t.Error(err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Error("unexpected status returned", res.StatusCode)
	}
}

func TestUpdateImageSuccessful(t *testing.T) {
	if createdContainer == nil {
		t.Skip("Skipping because create failed")
	}

	server := startServer()
	defer server.Close()

	addr := fmt.Sprintf("%s/images/%s", server.URL, createdContainer.ImageID)
	req, err := http.NewRequest("PUT", addr, nil)
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

func TestUpdateCollaboratorByProjectIDSuccessful(t *testing.T) {
	server := startServer()
	defer server.Close()

	collaborator := &schemas.Collaborator{
		Name:    "Drake",
		Email:   "drizzy@bowery.io",
		MACAddr: "30:52:my:ci:ty",
	}

	var data bytes.Buffer
	encoder := json.NewEncoder(&data)
	err := encoder.Encode(collaborator)
	if err != nil {
		t.Error(err)
	}

	addr := fmt.Sprintf("%s/projects/%s/collaborators", server.URL, createdContainer.ImageID)
	req, err := http.NewRequest("PUT", addr, &data)
	if err != nil {
		t.Error(err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer res.Body.Close()

	var resBody requests.CollaboratorRes
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resBody)
	if err != nil {
		t.Error(err)
	}

	if resBody.Status != requests.StatusUpdated {
		t.Error(resBody.Error)
	}
}

func TestGetProjectByIDSuccessful(t *testing.T) {
	server := startServer()
	defer server.Close()

	addr := fmt.Sprintf("%s/projects/%s", server.URL, createdContainer.ImageID)
	res, err := http.Get(addr)
	if err != nil {
		t.Error(err)
	}
	defer res.Body.Close()

	var resBody requests.ProjectRes
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resBody)
	if err != nil {
		t.Error(err)
	}

	if resBody.Status != requests.StatusFound {
		t.Error(resBody.Error)
	}

	if resBody.Project.ID != createdContainer.ImageID {
		t.Error("unexpected result", "retrieved project with incorrect id")
	}

	if resBody.Project.Collaborators[0].Name != "Drake" {
		t.Error("unexpected result", "could not find correct collaborator")
	}

	testProject = resBody.Project
}

func TestUpdateProjectByIDSuccessful(t *testing.T) {
	testProject.Collaborators[0].Permissions = map[string]bool{}
	testProject.Collaborators[0].Permissions["canEdit"] = true

	newCollaborator := schemas.Collaborator{
		Name:    "Lil Wayne",
		Email:   "tunechi@bowery.io",
		MACAddr: "po:pb:ot:tl:es",
	}
	testProject.Collaborators = append(testProject.Collaborators, newCollaborator)

	server := startServer()
	defer server.Close()

	var reqBody requests.ProjectReq
	var data bytes.Buffer

	reqBody.Project = testProject
	reqBody.MACAddr = "30:52:my:ci:ty"
	encoder := json.NewEncoder(&data)
	err := encoder.Encode(reqBody)
	if err != nil {
		t.Error(err)
	}

	addr := fmt.Sprintf("%s/projects/%s", server.URL, testProject.ID)
	req, err := http.NewRequest("PUT", addr, &data)
	if err != nil {
		t.Error(err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
	}

	var resBody requests.ProjectRes
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resBody)
	if err != nil {
		t.Error(err)
	}

	if resBody.Status != requests.StatusUpdated {
		t.Error(resBody.Error)
	}
}

func TestUpdateProjectByIDInsufficientPermissions(t *testing.T) {
	testProject.Collaborators[1].Permissions = map[string]bool{}
	testProject.Collaborators[1].Permissions["canEdit"] = true

	server := startServer()
	defer server.Close()

	var reqBody requests.ProjectReq
	var data bytes.Buffer

	reqBody.Project = testProject
	reqBody.MACAddr = "po:pb:ot:tl:es"
	encoder := json.NewEncoder(&data)
	err := encoder.Encode(reqBody)
	if err != nil {
		t.Error(err)
	}

	addr := fmt.Sprintf("%s/projects/%s", server.URL, testProject.ID)
	req, err := http.NewRequest("PUT", addr, &data)
	if err != nil {
		t.Error(err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
	}

	var resBody requests.ProjectRes
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resBody)
	if err != nil {
		t.Error(err)
	}

	if resBody.Status == requests.StatusUpdated {
		t.Error("unexpected status", resBody.Status)
	}

	if resBody.Error() != "insufficient permissions" {
		t.Error("unexpected error", resBody.Error())
	}
}

func TestSaveContainerSuccessful(t *testing.T) {
	if createdContainer == nil {
		t.Skip("Skipping because save failed")
	}
	server := startServer()
	defer server.Close()

	addr := fmt.Sprintf("%s/containers/%s/save?mac_addr=%s", server.URL, createdContainer.ID, url.QueryEscape(testProject.Collaborators[0].MACAddr))
	req, err := http.NewRequest("PUT", addr, nil)
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

func TestSaveContainerInsufficientPermissions(t *testing.T) {
	server := startServer()
	defer server.Close()

	addr := fmt.Sprintf("%s/containers/%s/save?mac_addr=%s", server.URL, createdContainer.ID, url.QueryEscape(testProject.Collaborators[1].MACAddr))
	req, err := http.NewRequest("PUT", addr, nil)
	if err != nil {
		t.Error(err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer res.Body.Close()

	var resBody requests.Res
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resBody)
	if err != nil {
		t.Error(err)
	}

	if resBody.Status != requests.StatusFailed {
		t.Error("unexpected status returned", resBody.Status)
	}

	if resBody.Error() != "insufficient permissions" {
		t.Error("unexpected error", resBody.Error())
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
