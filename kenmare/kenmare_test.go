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
	testImageID = "123"
	renderer    = render.New(render.Options{
		IndentJSON:    true,
		IsDevelopment: true,
	})
)

func TestCreateContainerSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(testCreateContainerHandlerSuccess))
	defer server.Close()
	config.KenmareAddr = server.URL

	_, err := CreateContainer(testImageID)
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

func TestDeleteContainerSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(testDeleteContainerHandlerSuccess))
	defer server.Close()
	config.KenmareAddr = server.URL

	err := DeleteContainer(testImageID)
	if err != nil {
		t.Error(err)
	}
}

func testDeleteContainerHandlerSuccess(rw http.ResponseWriter, req *http.Request) {
	renderer.JSON(rw, http.StatusOK, map[string]string{
		"status": requests.StatusRemoved,
	})
}
