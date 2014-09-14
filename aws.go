// Copyright 2014 Bowery, Inc.
// AWS ec2 management.
package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/mitchellh/goamz/aws"
	"github.com/mitchellh/goamz/ec2"
)

var (
	validAMIs = []string{
		"ami-9460ccfc", // this will change
	}
	validInstanceTypes = []string{
		"t1.micro",
		"m1.small",
		"m1.medium",
		"m1.large",
	}
	defaultSecurityGroup = "sg-70e0851a"
	requiredPorts        = []int{32056, 32058}
	suggestedPorts       = []int{22, 80, 3306, 6379, 8080, 27017}
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
// ami and instanceType. It returns the public address and the instance id
// on success. An error is returned if it can't be created or the state can't
// be retrieved.
func (c *AWSClient) CreateInstance(ami, instanceType, appID string, ports []int) (addr string, id string, err error) {
	// An ami id and instance type are required.
	if ami == "" || instanceType == "" {
		return "", "", errors.New("ami id and instance type required.")
	}

	err = validateConfig(ami, instanceType)
	if err != nil {
		return "", "", err
	}

	securityGroupId := defaultSecurityGroup

	// Create a new security group if ports are provided.
	if len(ports) > 0 {
		securityGroupId, err = c.createSecurityGroup(appID, ports)
		if err != nil {
			return "", "", err
		}
	}

	// Select first key.
	keys, err := c.client.KeyPairs(nil, nil)
	if err != nil {
		return "", "", err
	}

	// Set instance config.
	opts := &ec2.RunInstances{
		ImageId:      ami,
		MinCount:     1,
		MaxCount:     1,
		InstanceType: instanceType,
		SecurityGroups: []ec2.SecurityGroup{
			ec2.SecurityGroup{
				Id: securityGroupId,
			},
		},
	}

	if len(keys.Keys) > 0 {
		opts.KeyName = keys.Keys[0].Name
	}

	// Send RunInstance request.
	res, err := c.client.RunInstances(opts)
	if err != nil {
		return "", "", err
	}

	if len(res.Instances) != 1 {
		return "", "", errors.New("Failed to create required number of instances.")
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
			return "", "", err
		}

		if len(res.Reservations) != 1 {
			return "", "", errors.New("Unexpected response.")
		}

		instance := res.Reservations[0].Instances[0]
		state := instance.State.Name
		if state == "running" {
			return instance.PublicIpAddress, instanceID, nil
		}
	}
}

// RemoveInstances terminates the ec2 instance with the given id.
func (c *AWSClient) RemoveInstance(instanceID string) error {
	if instanceID == "" {
		return errors.New("instance id is required.")
	}

	_, err := c.client.TerminateInstances([]string{instanceID})
	if err != nil {
		return err
	}

	return nil
}

// createSecurityGroup creates a new security group with
// the provided ports. All ports are fully accessible and
// operate over TCP.
func (c *AWSClient) createSecurityGroup(appID string, ports []int) (string, error) {
	// Create new security group.
	res, err := c.client.CreateSecurityGroup(ec2.SecurityGroup{
		Name:        fmt.Sprintf("Bowery Security Group %s", appID),
		Description: fmt.Sprintf("Bowery Security Group for Application %s", appID),
	})

	if err != nil {
		return "", err
	}

	id := res.Id
	perms := []ec2.IPPerm{}

	// Add unique ports.
	for _, p := range ports {
		for _, r := range requiredPorts {
			if p != r {
				ports = append(ports, r)
			}
		}

		for _, s := range suggestedPorts {
			if p != s {
				ports = append(ports, s)
			}
		}
	}

	// Create ec2.IPPerm.
	for _, p := range ports {
		perms = append(perms, ec2.IPPerm{
			Protocol:  "tcp",
			FromPort:  p,
			ToPort:    p,
			SourceIPs: []string{"0.0.0.0/0"},
		})
	}

	// Send ingress request.
	group := ec2.SecurityGroup{Id: id}
	_, err = c.client.AuthorizeSecurityGroup(group, perms)
	if err != nil {
		return "", err
	}

	return id, nil
}

func validateConfig(ami, instanceType string) error {
	isValidAMI := false
	for _, a := range validAMIs {
		if a == ami {
			isValidAMI = true
			break
		}
	}

	if !isValidAMI {
		return fmt.Errorf("%s is an invalid ami", ami)
	}

	isValidInstanceType := false
	for _, i := range validInstanceTypes {
		if i == instanceType {
			isValidInstanceType = true
			break
		}
	}

	if !isValidInstanceType {
		return fmt.Errorf("%s is an invalid instance type", instanceType)
	}

	return nil
}
