package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Bowery/gopackages/config"
	"github.com/Bowery/gopackages/requests"
	"github.com/Bowery/gopackages/schemas"
	"github.com/gorilla/mux"
	"github.com/orchestrate-io/gorc"
)

var (
	createdContainer *schemas.Container
)

func init() {
	db = gorc.NewClient(config.OrchestrateDevKey)
	env = "testing" // Disables the aws features.
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
	res, err := http.Get(addr)
	if err != nil {
		t.Error(err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Error("unexpected status returned", res.StatusCode)
	}
}

func TestSaveContainerSuccessful(t *testing.T) {
	if createdContainer == nil {
		t.Skip("Skipping because save failed")
	}
	server := startServer()
	defer server.Close()

	addr := fmt.Sprintf("%s/containers/%s/save", server.URL, createdContainer.ID)
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
