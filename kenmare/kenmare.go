// Copyright 2014 Bowery, Inc.

package kenmare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Bowery/gopackages/config"
	"github.com/Bowery/gopackages/requests"
	"github.com/Bowery/gopackages/schemas"
)

// CreateContainer requests kenmare to create a new container.
func CreateContainer(imageID string) (*schemas.Container, error) {
	var data bytes.Buffer
	reqBody := requests.ContainerReq{
		ImageID: imageID,
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

// CreateContainer requests kenmare to delete a container.
func DeleteContainer(imageID string) error {
	addr := fmt.Sprintf("%s/containers/%s", config.KenmareAddr, imageID)
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
