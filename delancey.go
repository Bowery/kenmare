// Copyright 2014 Bowery, Inc.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/Bowery/gopackages/config"
	"github.com/Bowery/gopackages/requests"
	"github.com/Bowery/gopackages/schemas"
)

type commandsReq struct {
	AppID string   `json:"appID"`
	Cmds  []string `json:"cmds"`
}

// DelanceyPassword sends a request to set the password on the agent.
func DelanceyPassword(app *schemas.Application) error {
	addr := net.JoinHostPort(app.Location, config.BoweryAgentProdSyncPort)
	resp, err := http.PostForm(fmt.Sprintf("http://%s/password", addr), url.Values{
		"user": {app.User}, "password": {app.Password},
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	res := new(requests.Res)
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(res)
	if err != nil {
		return err
	}

	if res.Status != requests.StatusSuccess {
		return res
	}

	return nil
}

// DelanceyExec sends commands to a Delancey agent to be executed.
func DelanceyExec(app schemas.Application, cmds []string) error {
	req := &commandsReq{
		AppID: app.ID,
		Cmds:  cmds,
	}

	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	err := encoder.Encode(req)
	if err != nil {
		return err
	}

	url := net.JoinHostPort(app.Location, config.BoweryAgentProdSyncPort)
	res, err := http.Post(fmt.Sprintf("http://%s/commands", url), "application/json", &body)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	execRes := new(requests.Res)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(execRes)
	if err != nil {
		return err
	}

	if execRes.Status == requests.StatusSuccess {
		return nil
	}

	return execRes
}
