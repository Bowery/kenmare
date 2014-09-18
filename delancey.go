// Copyright 2014 Bowery, Inc.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/Bowery/gopackages/config"
	"github.com/Bowery/gopackages/requests"
	"github.com/Bowery/gopackages/schemas"
)

type commandsReq struct {
	AppID string   `json:"appID"`
	Cmds  []string `json:"cmds"`
}

func DelanceyExec(app schemas.Application, cmds []string) error {
	return nil
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

	execRes := new(Res)
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(execRes)
	if err != nil {
		return err
	}

	if execRes.Status == requests.STATUS_SUCCESS {
		return nil
	}

	return execRes
}
