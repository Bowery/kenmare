// Copyright 2014 Bowery, Inc.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"

	"code.google.com/p/go-uuid/uuid"
	"github.com/Bowery/delancey/delancey"
	"github.com/Bowery/gopackages/config"
	"github.com/Bowery/gopackages/docker"
	"github.com/Bowery/gopackages/docker/quay"
	"github.com/Bowery/gopackages/requests"
	"github.com/Bowery/gopackages/schemas"
	"github.com/Bowery/gopackages/util"
	"github.com/Bowery/gopackages/web"
	"github.com/gorilla/mux"
	"github.com/orchestrate-io/gorc"
	"github.com/stathat/go"
	"github.com/unrolled/render"
)

var routes = []web.Route{
	{"GET", "/", indexHandler, false},
	{"GET", "/healthz", healthzHandler, false},
	{"GET", "/environments/{id}", getEnvironmentByIDHandler, false},
	{"PUT", "/environments/{id}", updateEnvironmentByIDHandler, false},
	{"GET", "/environments/{id}/collaborators", getCollaboratorsByEnvIDHandler, false},
	{"PUT", "/environments/{id}/collaborators", updateCollaboratorByEnvID, false},
	{"POST", "/containers", createContainerHandler, false},
	{"GET", "/containers/{id}", getContainerByIDHandler, false},
	{"PUT", "/containers/{id}/save", saveContainerByIDHandler, false},
	{"DELETE", "/containers/{id}", removeContainerByIDHandler, false},
	{"PUT", "/images/{id}", updateImageByIDHandler, false},
	{"GET", "/export/{imageID}", exportHandler, false},
	{"GET", "/tar/{imageID}", getTarHandler, false},
}

var renderer = render.New(render.Options{
	IndentJSON:    true,
	IsDevelopment: true,
})

// indexHandler shows the home page.
func indexHandler(rw http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(rw, "Bowery Environment Manager")
}

// healthzHandler displays health.
func healthzHandler(rw http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(rw, "ok")
}

// getEnvironmentByIDHandler gets an environment and associated information.
func getEnvironmentByIDHandler(rw http.ResponseWriter, req *http.Request) {
	// todo(steve)
	renderer.JSON(rw, http.StatusOK, map[string]interface{}{
		"status": requests.StatusFound,
	})
}

// updateEnvironmentByIDHandler updates an environment.
func updateEnvironmentByIDHandler(rw http.ResponseWriter, req *http.Request) {
	// todo(steve)
	renderer.JSON(rw, http.StatusOK, map[string]interface{}{
		"status": requests.StatusSuccess,
	})
}

// getCollaboratorsByEnvIDHandler retrieves a list of collaborators for a
// specific environment.
func getCollaboratorsByEnvIDHandler(rw http.ResponseWriter, req *http.Request) {
	// todo(steve)
	renderer.JSON(rw, http.StatusOK, map[string]interface{}{
		"status":        requests.StatusFound,
		"collaborators": []*schemas.Collaborator{},
	})
}

// updateCollaboratorByEnvID creates/updates a collaborator for a
// specific environment.
func updateCollaboratorByEnvID(rw http.ResponseWriter, req *http.Request) {
	// todo(steve)
	renderer.JSON(rw, http.StatusOK, map[string]interface{}{
		"status":       requests.StatusUpdated,
		"collaborator": schemas.Collaborator{},
	})
}

// createContainerHandler creates a container on an available Google Cloud instance.
// If provided, the container created will be based on the `imageID`. During
// the creation process, if Kenmare detects the instance pool is below
// it's threshold, it will refill the pool in a separate routine.
func createContainerHandler(rw http.ResponseWriter, req *http.Request) {
	var body requests.ContainerReq
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&body)
	if err != nil {
		renderer.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.StatusFailed,
			"error":  err.Error(),
		})
		return
	}

	// Verify environment & collaborator.
	var environment schemas.Environment
	var collaborator schemas.Collaborator
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {

	}()

	go func() {

	}()

	wg.Wait()

	if body.ImageID == "" {
		environment = schemas.Environment{
			ID:            uuid.New(),
			CreatedAt:     time.Now(),
			Licenses:      0,
			Collaborators: []*schemas.Collaborator{},
		}
		_, err = db.Put(schemas.EnvironmentsCollection, environment.ID, environment)
	} else {
		environment, err = getEnvironment(body.ImageID)
	}

	if err != nil {
		renderer.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.StatusFailed,
			"error":  err.Error(),
		})
		return
	}

	container := &schemas.Container{
		ID:        uuid.New(),
		ImageID:   environment.ID,
		LocalPath: body.LocalPath,
		CreatedAt: time.Now(),
	}

	// Get the instance to use from Google Cloud.
	if env != "testing" {
		start := time.Now()
		go pusherC.Publish("instance:0", "progress", fmt.Sprintf("container-%s", container.ID))
		instance, err := ip.Get()
		if err != nil {
			data, _ := json.Marshal(map[string]string{"error": err.Error()})
			go pusherC.Publish(string(data), "error", fmt.Sprintf("container-%s", container.ID))
			renderer.JSON(rw, http.StatusInternalServerError, map[string]string{
				"status": requests.StatusFailed,
				"error":  err.Error(),
			})
			return
		}
		go pusherC.Publish("instance:1", "progress", fmt.Sprintf("container-%s", container.ID))
		container.Instance = instance
		container.Address = instance.Address
		elapsed := float64(time.Since(start).Nanoseconds() / 1000000)
		go stathat.PostEZValue("kenmare get instance overall time", config.StatHatKey, elapsed)
	}

	_, err = db.Put(schemas.ContainersCollection, container.ID, container)
	if err != nil {
		renderer.JSON(rw, http.StatusInternalServerError, map[string]string{
			"status": requests.StatusFailed,
			"error":  err.Error(),
		})
		return
	}

	// In a separate routine, reset the agent, launch the appropriate
	// container via the Docker remote api, and update Orchestrate with the
	// new information.
	if env != "testing" {
		go func() {
			start := time.Now()
			go pusherC.Publish("environment:0", "progress", fmt.Sprintf("container-%s", container.ID))

			// Wait till the agent is up and running.
			var backoff *util.Backoff
			for {
				if backoff != nil {
					if !backoff.Next() {
						return
					}
					<-time.After(backoff.Delay)
				} else {
					backoff = util.NewBackoff(0)
				}
				log.Println("checking agent availability")
				if delancey.Health(container.Address, time.Millisecond*70) == nil {
					break
				}
			}

			err := delancey.Create(container)
			if err != nil {
				data, _ := json.Marshal(map[string]string{"error": err.Error()})
				go pusherC.Publish(string(data), "error", fmt.Sprintf("container-%s", container.ID))
				return
			}
			go pusherC.Publish("environment:1", "progress", fmt.Sprintf("container-%s", container.ID))
			elapsed := float64(time.Since(start).Nanoseconds() / 1000000)
			go stathat.PostEZValue("kenmare delancey create container time", config.StatHatKey, elapsed)

			start = time.Now()
			_, err = db.Put(schemas.ContainersCollection, container.ID, container)
			if err != nil {
				log.Println(err)
				return
			}
			elapsed = float64(time.Since(start).Nanoseconds() / 1000000)
			go stathat.PostEZValue("kenmare delancey update orchestrate container time", config.StatHatKey, elapsed)

			start = time.Now()
			data, err := json.Marshal(container)
			if err == nil {
				err = pusherC.Publish(string(data), "created", fmt.Sprintf("container-%s", container.ID))
				if err != nil {
					log.Println(err)
				}
			} else {
				log.Println(err)
			}
			elapsed = float64(time.Since(start).Nanoseconds() / 1000000)
			go stathat.PostEZValue("kenmare delancey update pubsub request time", config.StatHatKey, elapsed)
		}()
	}

	renderer.JSON(rw, http.StatusOK, map[string]interface{}{
		"status":    requests.StatusCreated,
		"container": container,
	})
}

// getContainerByIDHandler gets a container by the provided id.
func getContainerByIDHandler(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	containerID := vars["id"]

	container, err := getContainer(containerID)
	if err != nil {
		renderer.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.StatusFailed,
			"error":  err.Error(),
		})
		return
	}

	renderer.JSON(rw, http.StatusOK, map[string]interface{}{
		"status":    requests.StatusCreated,
		"container": container,
	})
}

// saveContainerByIDHandler saves a container by the provided id.
func saveContainerByIDHandler(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	containerID := vars["id"]

	container, err := getContainer(containerID)
	if err != nil {
		renderer.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.StatusFailed,
			"error":  err.Error(),
		})
		return
	}

	if env != "testing" {
		go func() {
			go pusherC.Publish("environment:0", "progress", fmt.Sprintf("container-%s", container.ID))
			err := delancey.Save(&container)
			if err != nil {
				data, _ := json.Marshal(map[string]string{"error": err.Error()})
				go pusherC.Publish(string(data), "error", fmt.Sprintf("container-%s", container.ID))
				return
			}
			go pusherC.Publish("", "saved", fmt.Sprintf("container-%s", container.ID))
		}()
	}

	renderer.JSON(rw, http.StatusOK, map[string]string{
		"status": requests.StatusUpdated,
	})
}

// removeContainerByIDHandler terminates a container and sets the instance
// as available.
func removeContainerByIDHandler(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	containerID := vars["id"]

	removestart := time.Now()
	container, err := getContainer(containerID)
	if err != nil {
		renderer.JSON(rw, http.StatusBadRequest, map[string]string{
			"status": requests.StatusFailed,
			"error":  err.Error(),
		})
		return
	}

	// In separate routines, reset the agent and recycle the instance.
	if env != "testing" {
		go func() {
			start := time.Now()
			log.Println("calling delancey delete")
			err := delancey.Delete(&container)
			if err != nil {
				// TODO: handle error
				fmt.Println(err)
				return
			}
			log.Println("successfully deleted")
			elapsed := float64(time.Since(start).Nanoseconds() / 1000000)
			go stathat.PostEZValue("kenmare remove container by id delancey request time", config.StatHatKey, elapsed)

			start = time.Now()
			log.Println("calling delete instance")
			err = ip.Remove(container.Instance)
			if err != nil {
				// TODO: handle error
				fmt.Println(err)
			}
			log.Println("successfully deleted")
			elapsed = float64(time.Since(start).Nanoseconds() / 1000000)
			go stathat.PostEZValue("kenmare remove container by id delete instance time", config.StatHatKey, elapsed)
		}()
	}

	db.Delete(schemas.ContainersCollection, container.ID)
	renderer.JSON(rw, http.StatusOK, map[string]string{
		"status": requests.StatusRemoved,
	})
	elapsed := float64(time.Since(removestart).Nanoseconds() / 1000000)
	go stathat.PostEZValue("kenmare remove container by id request time", config.StatHatKey, elapsed)
}

// updateImageByIDHandler notifies clients using the image id that there's been
// an update, and tells all Delancey instances to pull the image down.
func updateImageByIDHandler(rw http.ResponseWriter, req *http.Request) {
	// This route can't do anything in the test env.
	if env == "testing" {
		renderer.JSON(rw, http.StatusOK, map[string]string{
			"status": requests.StatusUpdated,
		})
		return
	}
	vars := mux.Vars(req)
	imageID := vars["id"]

	// Get all containers here to publish ones with matching image ids, and later
	// to get running instances.
	containers, err := searchContainers("*")
	if err != nil {
		renderer.JSON(rw, http.StatusInternalServerError, map[string]string{
			"status": requests.StatusFailed,
			"error":  err.Error(),
		})
		return
	}

	for _, container := range containers {
		if container.ImageID == imageID {
			go pusherC.Publish("updated", "update", fmt.Sprintf("container-%s", container.ID))
		}
	}

	instances, err := searchInstances("*")
	if err != nil {
		renderer.JSON(rw, http.StatusInternalServerError, map[string]string{
			"status": requests.StatusFailed,
			"error":  err.Error(),
		})
		return
	}

	for _, container := range containers {
		instances = append(instances, *container.Instance)
	}
	var wg sync.WaitGroup
	var m sync.Mutex

	for _, instance := range instances {
		wg.Add(1)
		go func(inst schemas.Instance) {
			defer wg.Done()

			e := delancey.PullImage(inst.Address, imageID)
			if e != nil {
				m.Lock()
				err = e
				m.Unlock()
			}
		}(instance)
	}

	wg.Wait()
	if err != nil {
		renderer.JSON(rw, http.StatusInternalServerError, map[string]string{
			"status": requests.StatusFailed,
			"error":  err.Error(),
		})
		return
	}

	renderer.JSON(rw, http.StatusOK, map[string]string{
		"status": requests.StatusUpdated,
	})
}

func exportHandler(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	imageID := vars["imageID"]

	script := `#!/bin/bash
set -e
mp={{.ImageID}} # mount point
curl -L -f {{.Host}}/{{.ImageID}} | tar -xzvf -
sudo mkdir -p /tmp/${mp}
hash=$(ls -d */ | sed 's|/||g')
sudo tar xvf ${hash}/layer.tar -C /tmp/${mp}
sudo mkdir -p /tmp/${mp}/proc /tmp/${mp}/dev /tmp/${mp}/dev/pts /tmp/${mp}/sys /tmp/${mp}/etc
sudo mount -o bind /proc /tmp/${mp}/proc
sudo mount -o bind /dev /tmp/${mp}/dev
sudo mount -o bind /dev/pts /tmp/${mp}/dev/pts
sudo mount -o bind /sys /tmp/${mp}/sys
sudo cp /etc/resolv.conf /tmp/${mp}/etc/resolv.conf
echo "To use, run 'sudo chroot /tmp/${mp}/ /bin/bash'`

	t, err := template.New("script").Parse(script)
	if err != nil {
		renderer.JSON(rw, http.StatusInternalServerError, map[string]string{
			"status": requests.StatusFailed,
			"error":  err.Error(),
		})
		return
	}

	var buf bytes.Buffer

	err = t.Execute(&buf, map[string]string{
		"Host":    config.ExportAddr,
		"ImageID": imageID,
	})
	if err != nil {
		renderer.JSON(rw, http.StatusInternalServerError, map[string]string{
			"status": requests.StatusFailed,
			"error":  err.Error(),
		})
		return
	}

	res := requests.ExportRes{
		Docker: fmt.Sprintf("curl -L -f %s/tar/%s | docker load", config.KenmareAddr, imageID),
		Shell:  buf.String(),
	}
	res.Res = new(requests.Res)
	res.Status = requests.StatusSuccess

	renderer.JSON(rw, http.StatusOK, res)
}

func getTarHandler(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	imageID := vars["imageID"]

	err := quay.SquashImage(docker.DefaultAuth, config.DockerBaseImage+":"+imageID, rw)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}
}

// getEnvironment retrieves an environment from Orchestrate.
func getEnvironment(id string) (schemas.Environment, error) {
	envData, err := db.Get(schemas.EnvironmentsCollection, id)
	if err != nil {
		return schemas.Environment{}, err
	}

	environment := schemas.Environment{}
	err = envData.Value(&environment)
	if err != nil {
		return schemas.Environment{}, err
	}

	return environment, nil
}

// getContainer retrieves a container from Orchestrate.
func getContainer(id string) (schemas.Container, error) {
	start := time.Now()
	containerData, err := db.Get(schemas.ContainersCollection, id)
	if err != nil {
		return schemas.Container{}, err
	}

	container := schemas.Container{}
	err = containerData.Value(&container)
	if err != nil {
		return schemas.Container{}, err
	}
	elapsed := float64(time.Since(start).Nanoseconds() / 1000000)
	go stathat.PostEZValue("kenmare get container from orchestrate time", config.StatHatKey, elapsed)
	return container, nil
}

// getContainer retrieves a collaborator from Orchestrate.
func getCollaborator(id string) (schemas.Collaborator, error) {
	collaboratorData, err := db.Get(schemas.CollaboratorsCollection, id)
	if err != nil {
		return schemas.Collaborator{}, err
	}

	collaborator := schemas.Collaborator{}
	err = collaboratorData.Value(&collaborator)
	if err != nil {
		return schemas.Collaborator{}, err
	}

	return collaborator, nil
}

func searchContainers(query string) ([]schemas.Container, error) {
	var containers []schemas.Container

	data, _, err := search(schemas.ContainersCollection, query, true)
	if err != nil {
		return nil, err
	}

	for _, result := range data {
		var container schemas.Container

		err := result.Value(&container)
		if err != nil {
			return nil, err
		}

		containers = append(containers, container)
	}

	return containers, nil
}

func searchInstances(query string) ([]schemas.Instance, error) {
	var instances []schemas.Instance

	data, _, err := search(schemas.InstancesCollection, query, true)
	if err != nil {
		return nil, err
	}

	for _, result := range data {
		var instance schemas.Instance

		err := result.Value(&instance)
		if err != nil {
			return nil, err
		}

		instances = append(instances, instance)
	}

	return instances, nil
}

// search returns the query results on a collection, paging the results if true.
// The search results are returned, and the total count of items found in the db.
func search(collection, query string, page bool) ([]gorc.SearchResult, uint64, error) {
	data, err := db.Search(collection, query, 100, 0)
	if err != nil {
		return nil, 0, err
	}
	results := data.Results

	for page && data.HasNext() {
		data, err = db.SearchGetNext(data)
		if err != nil {
			return nil, 0, err
		}

		results = append(results, data.Results...)
	}

	return results, data.TotalCount, nil
}
