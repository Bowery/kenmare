// Copyright 2014 Bowery, Inc.
package main

type Environment struct {
	ID           string `json:"id"`
	AMI          string `json:"ami"`
	InstanceType string `json:"instanceType"`
	Ports        []int  `json:"ports"`
}

type Event struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Body string `json:"body"`
}
