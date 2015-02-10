// Copyright 2014 Bowery, Inc.

package kenmare

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Bowery/gopackages/config"
	"github.com/Bowery/gopackages/requests"
	"github.com/Bowery/gopackages/schemas"
	"github.com/unrolled/render"
)

var (
	testImageID     = "123"
	testContainerID = "456"
	testProjectID   = "789"
	renderer        = render.New(render.Options{
		IndentJSON:    true,
		IsDevelopment: true,
	})
)

func TestCreateContainerSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(testCreateContainerHandlerSuccess))
	defer server.Close()
	config.KenmareAddr = server.URL

	_, err := CreateContainer(testImageID, "/Users/chiefkeef/dev/website")
	if err != nil {
		t.Error(err)
	}
}

func testCreateContainerHandlerSuccess(rw http.ResponseWriter, req *http.Request) {
	renderer.JSON(rw, http.StatusOK, map[string]interface{}{
		"status":    requests.StatusCreated,
		"container": schemas.Container{},
	})
}

func TestSaveContainerSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(testSaveContainerHandlerSuccess))
	defer server.Close()
	config.KenmareAddr = server.URL

	err := SaveContainer(testContainerID)
	if err != nil {
		t.Error(err)
	}
}

func testSaveContainerHandlerSuccess(rw http.ResponseWriter, req *http.Request) {
	renderer.JSON(rw, http.StatusOK, map[string]string{
		"status": requests.StatusUpdated,
	})
}

func TestDeleteContainerSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(testDeleteContainerHandlerSuccess))
	defer server.Close()
	config.KenmareAddr = server.URL

	err := DeleteContainer(testContainerID)
	if err != nil {
		t.Error(err)
	}
}

func testDeleteContainerHandlerSuccess(rw http.ResponseWriter, req *http.Request) {
	renderer.JSON(rw, http.StatusOK, map[string]string{
		"status": requests.StatusRemoved,
	})
}

func TestUpdateImageSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(testUpdateImageHandlerSuccess))
	defer server.Close()
	config.KenmareAddr = server.URL

	err := UpdateImage(testContainerID)
	if err != nil {
		t.Error(err)
	}
}

func testUpdateImageHandlerSuccess(rw http.ResponseWriter, req *http.Request) {
	renderer.JSON(rw, http.StatusOK, map[string]string{
		"status": requests.StatusUpdated,
	})
}

func TestGetProjectSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(testGetProjectHandlerSuccess))
	defer server.Close()
	config.KenmareAddr = server.URL

	project, err := GetProject("1")
	if err != nil {
		t.Error(err)
	}

	if project.ID != "1" {
		t.Error("unexpected result")
	}
}

func testGetProjectHandlerSuccess(rw http.ResponseWriter, req *http.Request) {
	renderer.JSON(rw, http.StatusOK, map[string]interface{}{
		"status": requests.StatusFound,
		"project": schemas.Project{
			ID: "1",
		},
	})
}

func TestUpdateCollaboratorSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(testUpdateCollaboratorHandlerSuccess))
	defer server.Close()
	config.KenmareAddr = server.URL

	collaborator := &schemas.Collaborator{
		ID:      "1",
		Name:    "Steve",
		MACAddr: "01:23:45:67:89",
	}

	_, err := UpdateCollaborator(testProjectID, collaborator)
	if err != nil {
		t.Fatal(err)
	}
}

func testUpdateCollaboratorHandlerSuccess(rw http.ResponseWriter, req *http.Request) {
	renderer.JSON(rw, http.StatusOK, map[string]interface{}{
		"status": requests.StatusUpdated,
		"collaborator": schemas.Collaborator{
			ID:   "1",
			Name: "Steve",
		},
	})
}
