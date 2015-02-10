// Copyright 2014 Bowery, Inc.

package kenmare

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/Bowery/gopackages/config"
	"github.com/Bowery/gopackages/requests"
	"github.com/Bowery/gopackages/schemas"
)

// Errors that may occur.
var (
	ErrNoInstances = errors.New("There are no instances available right now. Please try again")
)

// CreateContainer requests kenmare to create a new container.
func CreateContainer(imageID, localPath string) (*schemas.Container, error) {
	var data bytes.Buffer
	reqBody := requests.ContainerReq{
		ImageID:   imageID,
		LocalPath: localPath,
	}
	encoder := json.NewEncoder(&data)
	err := encoder.Encode(reqBody)
	if err != nil {
		return nil, err
	}

	addr := fmt.Sprintf("%s/containers", config.KenmareAddr)
	res, err := http.Post(addr, "application/json", &data)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var resBody requests.ContainerRes
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resBody)
	if err != nil {
		return nil, err
	}

	if resBody.Status != requests.StatusCreated {
		// If the error matches return var.
		if resBody.Error() == ErrNoInstances.Error() {
			return nil, ErrNoInstances
		}

		return nil, resBody
	}

	return resBody.Container, nil
}

// SaveContainer requests kenmare to save a container.
func SaveContainer(containerID string) error {
	addr := fmt.Sprintf("%s/containers/%s/save", config.KenmareAddr, containerID)
	req, err := http.NewRequest("PUT", addr, nil)
	if err != nil {
		return err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	var resBody requests.Res
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resBody)
	if err != nil {
		return err
	}

	if resBody.Status != requests.StatusUpdated {
		return &resBody
	}

	return nil
}

// DeleteContainer requests kenmare to delete a container.
func DeleteContainer(containerID string) error {
	addr := fmt.Sprintf("%s/containers/%s", config.KenmareAddr, containerID)
	req, err := http.NewRequest("DELETE", addr, nil)
	if err != nil {
		return err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	var resBody requests.Res
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resBody)
	if err != nil {
		return err
	}

	if resBody.Status != requests.StatusRemoved {
		return &resBody
	}

	return nil
}

// UpdateImage requests kenmare to update an image and notify
// users of the changes.
func UpdateImage(imageID string) error {
	addr := fmt.Sprintf("%s/images/%s", config.KenmareAddr, imageID)
	req, err := http.NewRequest("PUT", addr, nil)
	if err != nil {
		return err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	var resBody requests.Res
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resBody)
	if err != nil {
		return err
	}

	if resBody.Status != requests.StatusUpdated {
		return &resBody
	}

	return nil
}

// Export calls the export endpoint on the kenmare server and returns the body
func Export(imageID string) (*requests.ExportRes, error) {
	addr := fmt.Sprintf("%s/export/%s", config.KenmareAddr, imageID)
	res, err := http.Get(addr)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var resBody requests.ExportRes
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resBody)
	if err != nil {
		return nil, err
	}

	if resBody.Status != requests.StatusSuccess {
		return nil, &resBody
	}

	return &resBody, nil
}

// GetProject requests kenmare for a project.
func GetProject(id string) (*schemas.Project, error) {
	if id == "" {
		return nil, errors.New("id required")
	}

	addr := fmt.Sprintf("%s/projects/%s", config.KenmareAddr, id)
	res, err := http.Get(addr)
	if err != nil {
		return nil, err
	}

	var resBody requests.ProjectRes
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resBody)
	if err != nil {
		return nil, err
	}

	if resBody.Status != requests.StatusFound {
		return nil, &resBody
	}

	return resBody.Project, nil
}

// UpdateCollaborator requests kenmare to update or create
// a collaborator for a specific project. If the quota for
// collaborators on the project has been met, and error
// will be thrown.
func UpdateCollaborator(projectID string, collaborator *schemas.Collaborator) (*schemas.Collaborator, error) {
	if projectID == "" {
		return nil, errors.New("project id required")
	}

	var data bytes.Buffer
	encoder := json.NewEncoder(&data)
	err := encoder.Encode(collaborator)
	if err != nil {
		return nil, err
	}

	addr := fmt.Sprintf("%s/projects/%s/collaborators", config.KenmareAddr, projectID)
	req, err := http.NewRequest("PUT", addr, &data)
	if err != nil {
		return nil, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var resBody requests.CollaboratorRes
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resBody)

	if resBody.Status != requests.StatusUpdated {
		return nil, &resBody
	}

	return resBody.Collaborator, nil
}
