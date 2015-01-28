// Copyright 2015 Bowery, Inc.

package main

import (
	"fmt"
	"math/big"
	"sync"
	"time"

	"code.google.com/p/go-uuid/uuid"
	"github.com/Bowery/delancey/delancey"
	"github.com/Bowery/gopackages/config"
	"github.com/Bowery/gopackages/schemas"
	"github.com/sjkaliski/go/src/crypto/rand"
	"github.com/stathat/go"
)

const (
	InstancePoolMin         = 20
	IntancePoolMinThreshold = 15
)

// InstancePool represents a collection of instances.
type InstancePool struct{}

// Allocate creates a new set of instances and adds
// them to the pool.
func (ip *InstancePool) Allocate(num int) error {
	var err error
	var wg sync.WaitGroup

	// Create instances in parallel.
	batchstart := time.Now()
	for i := 0; i < num; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			instancestart := time.Now()

			instance := &schemas.Instance{
				ID:         uuid.New(),
				InstanceID: fmt.Sprintf("bowery-%s", uuid.New()),
				Provider:   schemas.ProviderGoogleCloudPlatform,
			}

			fmt.Println("Creating instance", instance.InstanceID)
			e := gcloudC.CreateInstance(instance.InstanceID, config.BoweryBaseImage, "n1-standard-1", "http://bowery.sh/startup.sh")
			if e != nil {
				err = e
				return
			}

			fmt.Println("Checking instance", instance.InstanceID)
			addr, e := gcloudC.CheckInstance(instance.InstanceID)
			if e != nil {
				err = e
				return
			}
			instance.Address = addr

			fmt.Println("Tagging instance", instance.InstanceID)
			e = gcloudC.TagInstance(instance.InstanceID, []string{"spare"})
			if e != nil {
				err = e
				return
			}

			fmt.Println("Saving instance", instance.InstanceID)
			_, e = db.Put(schemas.InstancesCollection, instance.ID, instance)
			if e != nil {
				err = e
				return
			}
			elapsed := float64(time.Since(instancestart).Nanoseconds() / 1000000)
			go stathat.PostEZValue("kenmare allocate instance time", config.StatHatKey, elapsed)
		}()
	}

	// Wait for all instances to be created and database is current
	wg.Wait()
	elapsed := float64(time.Since(batchstart).Nanoseconds() / 1000000)
	go stathat.PostEZValue("kenmare allocate batch instances time", config.StatHatKey, elapsed)
	return err
}

// Get get's an instance from the pool. Additional instances
// are allocated if the size dips below a threshold.
func (ip *InstancePool) Get() (*schemas.Instance, error) {
	start := time.Now()
	results, totalCount, err := search(schemas.InstancesCollection, "*", true)
	if err != nil {
		return nil, err
	}
	refresh := false
	refreshCheck := false

	// Check total for need to add to the pool.
	if totalCount == 0 {
		err = ip.Allocate(InstancePoolMin)
		if err != nil {
			return nil, err
		}
		refresh = true
	} else if totalCount <= IntancePoolMinThreshold {
		go ip.Allocate(InstancePoolMin)
		refresh = true
		refreshCheck = true
	}

	if refresh {
		results, _, err = search(schemas.InstancesCollection, "*", true)
		if err != nil {
			return nil, err
		}
	}
	elapsed := float64(time.Since(start).Nanoseconds() / 1000000)
	go stathat.PostEZValue("kenmare check instance pool time", config.StatHatKey, elapsed)

	// Fetch a current list of instances from the database.
	start = time.Now()
	instances := make([]schemas.Instance, len(results))
	for i, result := range results {
		err := result.Value(&instances[i])
		if err != nil {
			return nil, err
		}
	}
	elapsed = float64(time.Since(start).Nanoseconds() / 1000000)
	go stathat.PostEZValue("kenmare get instance list time", config.StatHatKey, elapsed)

	// Choose a random instance from the database, remove it and return
	// that to the client.
	start = time.Now()
	num, err := rand.Int(rand.Reader, big.NewInt(int64(len(instances))))
	if err != nil {
		return nil, err
	}

	instance := instances[num.Int64()]
	err = db.Delete(schemas.InstancesCollection, instance.ID)
	if err != nil {
		return nil, err
	}

	if !refresh || refreshCheck {
		err = delancey.Health(instance.Address, time.Millisecond*70)
		if err != nil {
			return ip.Get()
		}
	}

	// Update the status tag for the now-used instance.
	go func() {
		err = gcloudC.TagInstance(instance.InstanceID, []string{"live"})
		if err != nil {
			fmt.Println(err)
		}
		return
	}()
	elapsed = float64(time.Since(start).Nanoseconds() / 1000000)
	go stathat.PostEZValue("kenmare get instance from pool time", config.StatHatKey, elapsed)
	return &instance, nil
}

// Remove removes an instance from being active and restores
// it to the pool.
func (ip *InstancePool) Remove(instance *schemas.Instance) error {
	start := time.Now()
	// Add the instance back to the spare pool in the database.
	_, err := db.Put(schemas.InstancesCollection, instance.ID, instance)
	if err != nil {
		return err
	}

	// Re-tag the instance 'spare' on EC2.
	err = gcloudC.TagInstance(instance.InstanceID, []string{"spare"})
	if err != nil {
		return err
	}
	elapsed := float64(time.Since(start).Nanoseconds() / 1000000)
	go stathat.PostEZValue("kenmare return instance to pool time", config.StatHatKey, elapsed)
	return nil
}
