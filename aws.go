// Copyright 2014 Bowery, Inc.
// AWS ec2 management.
package main

import (
	"errors"
	"time"

	"github.com/mitchellh/goamz/aws"
	"github.com/mitchellh/goamz/ec2"
)

// AWSClient is a ec2 client.
type AWSClient struct {
	client *ec2.EC2
}

// NewAWSClient creates a new AWSClient. Valid accessKey and
// secretKey are required. Returns an error if unable to
// create the client.
func NewAWSClient(accessKey, secretKey string) (*AWSClient, error) {
	if accessKey == "" || secretKey == "" {
		return nil, errors.New("accessKey and secretKey required.")
	}

	auth, err := aws.GetAuth(accessKey, secretKey)
	if err != nil {
		return nil, err
	}

	// todo(steve): allow other regions.
	return &AWSClient{
		client: ec2.New(auth, aws.USEast),
	}, nil
}

// CreateInstance creates a new EC2 instances with the specified
// ami and instanceType. Returns the public address of the newly
// created instance. Returns an error if unable to create a new
// instance, or if there is an error checking the state.
func (c *AWSClient) CreateInstance(ami, instanceType string) (string, error) {
	if ami == "" || instanceType == "" {
		return "", errors.New("ami id and instance type required.")
	}

	opts := &ec2.RunInstances{
		ImageId:      ami,
		MinCount:     1,
		MaxCount:     1,
		InstanceType: instanceType,
	}

	// Send RunInstance request.
	res, err := c.client.RunInstances(opts)
	if err != nil {
		return "", err
	}

	if len(res.Instances) != 1 {
		return "", errors.New("Failed to create required number of instances.")
	}

	instanceID := res.Instances[0].InstanceId

	// Check the state of the instance every second. Once the
	// instance is "running" return the public address.
	// Note: the address is unavailable until it is in a
	// running state.
	for {
		<-time.After(time.Second)
		res, err := c.client.Instances([]string{instanceID}, nil)
		if err != nil {
			return "", err
		}

		if len(res.Reservations) != 1 {
			return "", errors.New("Unexpected response.")
		}

		instance := res.Reservations[0].Instances[0]
		state := instance.State.Name
		if state == "running" {
			return instance.PublicIpAddress, nil
		}
	}
}
