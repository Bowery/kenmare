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

// GetCollaborators retrieves a list of collaborators for a
// specific environment.
func GetCollaborators(envID string) ([]*schemas.Collaborator, error) {
	if envID == "" {
		return nil, errors.New("environment id required")
	}

	addr := fmt.Sprintf("%s/environments/%s/collaborators", config.KenmareAddr, envID)
	res, err := http.Get(addr)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var resBody requests.CollaboratorsRes
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resBody)
	if err != nil {
		return nil, err
	}

	if resBody.Status != requests.StatusFound {
		return nil, &resBody
	}

	return resBody.Collaborators, nil
}

// UpdateCollaborator requests kenmare to update or create
// a collaborator for a specific environment. If the quota for
// collaborators on the environment has been met, and error
// will be thrown.
func UpdateCollaborator(envID string, collaborator *schemas.Collaborator) (*schemas.Collaborator, error) {
	if envID == "" {
		return nil, errors.New("environment id required")
	}

	var data bytes.Buffer
	encoder := json.NewEncoder(&data)
	err := encoder.Encode(collaborator)
	if err != nil {
		return nil, err
	}

	addr := fmt.Sprintf("%s/environments/%s/collaborators", config.KenmareAddr, envID)
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
