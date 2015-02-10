// Copyright 2014 Bowery, Inc.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"time"

	"code.google.com/p/go-uuid/uuid"
	"github.com/Bowery/delancey/delancey"
	"github.com/Bowery/gopackages/config"
	"github.com/Bowery/gopackages/requests"
	"github.com/Bowery/gopackages/schemas"
	"github.com/Bowery/gopackages/web"
	"github.com/Bowery/kenmare/kenmare"
	"github.com/gorilla/mux"
	"github.com/orchestrate-io/gorc"
	"github.com/stathat/go"
	"github.com/unrolled/render"
)

// exportScript is used when exporting an environment.
const exportScript = `#!/bin/bash
set -e

id="{{.ImageID}}"
mp="/tmp/${id}" # Mount point
\mkdir -p "${id}"
\cd "${id}"
\curl -L -f "{{.Host}}/${id}" | \tar xzf -
sudo mkdir -p "${mp}"
hash="$(\ls -d */ | \sed 's|/||g')"
sudo tar xf "${hash}/layer.tar" -C "${mp}"
sudo mkdir -p "${mp}/"{proc,dev/{,pts},sys}
sudo mount -o bind /proc "${mp}/proc"
sudo mount -o bind /dev "${mp}/dev"
sudo mount -o bind /dev/pts "${mp}/dev/pts"
sudo mount -o bind /sys "${mp}/sys"
sudo cp /etc/resolv.conf "${mp}/etc/resolv.conf"
\cd ..
sudo rm -rf "${id}"

echo "To use, run 'sudo chroot \"${mp}\" /bin/bash'"
echo "To remove, run 'sudo umount -R \"${mp}/\"{proc,dev,sys}'"`

var routes = []web.Route{
	{"GET", "/", indexHandler, false},
	{"GET", "/healthz", healthzHandler, false},
	{"PUT", "/projects/{id}/collaborators", updateCollaboratorByProjectID, false},
	{"POST", "/containers", createContainerHandler, false},
	{"GET", "/containers/{id}", getContainerByIDHandler, false},
	{"PUT", "/containers/{id}/save", saveContainerByIDHandler, false},
	{"DELETE", "/containers/{id}", removeContainerByIDHandler, false},
	{"PUT", "/images/{id}", updateImageByIDHandler, false},
	{"GET", "/export/{imageID}", exportHandler, false},
}

var renderer = render.New(render.Options{
	IndentJSON:    true,
	IsDevelopment: true,
})

func indexHandler(rw http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(rw, "Bowery Environment Manager")
}

func healthzHandler(rw http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(rw, "ok")
}

// updateCollaboratorByProjectID creates/updates a collaborator for a
// specific project.
func updateCollaboratorByProjectID(rw http.ResponseWriter, req *http.Request) {
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

	imageID := body.ImageID
	if imageID == "" {
		imageID = uuid.New()
	}

	container := &schemas.Container{
		ID:        uuid.New(),
		ImageID:   imageID,
		LocalPath: body.LocalPath,
		CreatedAt: time.Now(),
	}

	// Get the instance to use from Google Cloud.
	if env != "testing" {
		instance, err := useRandomInstance()
		if err != nil {
			data, _ := json.Marshal(map[string]string{"error": err.Error()})
			go pusherC.Publish(string(data), "error", fmt.Sprintf("container-%s", container.ID))
			renderer.JSON(rw, http.StatusInternalServerError, map[string]string{
				"status": requests.StatusFailed,
				"error":  err.Error(),
			})
			return
		}

		container.Instance = instance
		container.Address = instance.Address
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
			// var backoff *util.Backoff
			// for {
			// 	if backoff != nil {
			// 		if !backoff.Next() {
			// 			return
			// 		}
			// 		<-time.After(backoff.Delay)
			// 	} else {
			// 		backoff = util.NewBackoff(0)
			// 	}
			// 	log.Println("checking agent availability")
			// 	if delancey.Health(container.Address, time.Millisecond*70) == nil {
			// 		break
			// 	}
			// }
			log.Println(delancey.Health(container.Address, 100*time.Millisecond))

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
			log.Println("putting instance in collection")
			_, err = db.Put(schemas.InstancesCollection, container.Instance.ID, container.Instance)
			if err != nil {
				// TODO: handle error
				fmt.Println(err)
			}
			log.Println("successfully stored instance")
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
// an update.
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

	// Get all containers here to publish ones with matching image ids.
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

	renderer.JSON(rw, http.StatusOK, map[string]string{
		"status": requests.StatusUpdated,
	})
}

// exportHandler generates the export scripts for an image.
func exportHandler(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	imageID := vars["imageID"]

	t, err := template.New("script").Parse(exportScript)
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
		Docker: fmt.Sprintf("curl -L -f %s/%s | docker load", config.ExportAddr, imageID),
		Shell:  buf.String(),
	}
	res.Res = new(requests.Res)
	res.Status = requests.StatusSuccess

	renderer.JSON(rw, http.StatusOK, res)
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

// useRandomInstance retrieves an instance to use removing it from the
// instances collection.
func useRandomInstance() (*schemas.Instance, error) {
	results, totalCount, err := search(schemas.InstancesCollection, "*", true)
	if err != nil {
		return nil, err
	}

	// If none exist, some will be created by the cron job.
	if totalCount <= 0 {
		return nil, kenmare.ErrNoInstances
	}

	// Get random instance from the list of results.
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(results))))
	if err != nil {
		return nil, err
	}

	instance := new(schemas.Instance)
	err = results[idx.Int64()].Value(instance)
	if err != nil {
		return nil, err
	}

	// Delete the instance from the collection so it can't be used.
	err = db.Delete(schemas.InstancesCollection, instance.ID)
	if err != nil {
		return nil, err
	}

	return instance, nil
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
