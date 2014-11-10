// Copyright 2014 Bowery, Inc.
// AWS ec2 management.
package main

import (
	"errors"
	"fmt"
	"time"

	"code.google.com/p/go-uuid/uuid"

	"github.com/Bowery/gopackages/config"
	"github.com/mitchellh/goamz/aws"
	"github.com/mitchellh/goamz/ec2"
)

var (
	validInstanceTypes = []string{
		"t1.micro",
		"m1.small",
		"m1.medium",
		"m1.large",
		"m3.medium",
		"m3.large",
	}
	defaultSecurityGroup = "sg-70e0851a"
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
func (c *AWSClient) CreateInstance(ami, instanceType, appID string, ports []int, useKeys bool) (string, error) {
	// An ami id and instance type are required.
	if ami == "" || instanceType == "" {
		return "", errors.New("ami id and instance type required.")
	}

	err := validateConfig(instanceType)
	if err != nil {
		return "", err
	}

	securityGroupId := defaultSecurityGroup

	// Create a new security group if ports are provided.
	if ports == nil || len(ports) == 0 {
		ports = []int{}
	}

	securityGroupId, err = c.createSecurityGroup(appID, ports)
	if err != nil {
		return "", err
	}

	// Select first key.
	keys, err := c.client.KeyPairs(nil, nil)
	if err != nil {
		return "", err
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

	if useKeys && len(keys.Keys) > 0 {
		opts.KeyName = keys.Keys[0].Name
	}

	// Send RunInstance request.
	res, err := c.client.RunInstances(opts)
	if err != nil {
		return "", err
	}

	if len(res.Instances) != 1 {
		return "", errors.New("Failed to create required number of instances.")
	}

	return res.Instances[0].InstanceId, nil
}

// CheckInstance checks the state of an instance every second.
// Once the instance is "running" return the address.
func (c *AWSClient) CheckInstance(instanceID string) (string, error) {
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

// SaveInstance takes a public ami snapshot of the ec2 instance
// with the given id.
func (c *AWSClient) SaveInstance(instanceID string) (string, error) {
	createOpts := ec2.CreateImage{
		InstanceId:  instanceID,
		Name:        "Bowery AMI " + uuid.New(),
		Description: "Bowery AMI " + uuid.New(),
		NoReboot:    true,
	}

	// Create new image.
	createRes, err := c.client.CreateImage(&createOpts)
	if err != nil {
		return "", err
	}
	imageID := createRes.ImageId

	// Poll image for status "available."
	isPending := true
	for isPending {
		<-time.After(5 * time.Second)
		res, err := c.client.Images([]string{imageID}, nil)
		if err != nil {
			return "", err
		}

		if res.Images == nil {
			return "", errors.New("no images found")
		}

		img := res.Images[0]
		if img.State == "failed" {
			return "", errors.New(img.StateReason)
		}

		if res.Images[0].State == "available" {
			isPending = false
		}
	}

	// Modify privacy.
	updateOpts := ec2.ModifyImageAttribute{
		AddGroups: []string{"all"},
	}
	_, err = c.client.ModifyImageAttribute(imageID, &updateOpts)
	if err != nil {
		return "", err
	}

	return imageID, nil
}

// ValidateKeys runs a simple query to verify
// the provided keys are valid.
func (c *AWSClient) ValidateKeys() bool {
	_, err := c.client.KeyPairs(nil, nil)
	if err != nil {
		return false
	}
	return true
}

// GetInstanceCount gets the total number of instances
// operated by the client.
func (c *AWSClient) GetInstanceCount() (int, error) {
	res, err := c.client.Instances([]string{}, nil)
	if err != nil {
		return 0, err
	}

	return len(res.Reservations), nil
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

	for _, r := range config.RequiredPorts {
		ports = append(ports, r)
	}

	for _, s := range config.SuggestedPorts {
		ports = append(ports, s)
	}

	duplicate := make(map[int]bool)
	j := 0
	for i, p := range ports {
		if !duplicate[p] {
			duplicate[p] = true
			ports[j] = ports[i]
			j++
		}
	}

	ports = ports[:j]

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

func validateConfig(instanceType string) error {
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
