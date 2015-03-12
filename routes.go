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
	"github.com/Bowery/gopackages/util"
	"github.com/Bowery/gopackages/web"
	"github.com/Bowery/kenmare/kenmare"
	"github.com/gorilla/mux"
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
	{"GET", "/projects/{id}", getProjectByIDHandler, false},
	{"PUT", "/projects/{id}", updateProjectByIDHandler, false},
	{"PUT", "/projects/{id}/collaborators", updateCollaboratorByProjectIDHandler, false},
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

// getProjectByIDHandler gets a project.
func getProjectByIDHandler(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	id := vars["id"]

	project, err := getProject(id)
	if err != nil {
		requests.ErrorJSON(rw, http.StatusBadRequest, requests.StatusFailed, err.Error())
		return
	}

	renderer.JSON(rw, http.StatusOK, map[string]interface{}{
		"status":  requests.StatusFound,
		"project": project,
	})
}

func updateProjectByIDHandler(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	projectID := vars["id"]

	// Get project. If no project is found, return error.
	currentProject, err := getProject(projectID)
	if err != nil {
		requests.ErrorJSON(rw, http.StatusBadRequest, requests.StatusFailed, err.Error())
		return
	}

	var body requests.ProjectReq
	decoder := json.NewDecoder(req.Body)
	err = decoder.Decode(&body)
	if err != nil {
		requests.ErrorJSON(rw, http.StatusBadRequest, requests.StatusFailed, err.Error())
		return
	}

	// Find collaborator in project.
	var currentCollaborator schemas.Collaborator
	for _, c := range currentProject.Collaborators {
		if c.MACAddr == body.MACAddr {
			currentCollaborator = c
			break
		}
	}

	// Make sure there is a valid collaborator and that person
	// is the creator. Only the creator can edit permissions.
	// In the future there will be a permission allowing a user
	// to edit other user's permissions, e.g. an admin.
	if currentCollaborator.ID == "" || currentProject.CreatorID != currentCollaborator.ID {
		requests.ErrorJSON(rw, http.StatusBadRequest, requests.StatusFailed, "insufficient permissions")
		return
	}

	updatedProject := body.Project

	// Update current project with changes.
	currentProject.Collaborators = updatedProject.Collaborators
	err = db.Set(schemas.ProjectsCollection, updatedProject.ID, updatedProject)
	if err != nil {
		requests.ErrorJSON(rw, http.StatusInternalServerError, requests.StatusFailed, err.Error())
		return
	}

	renderer.JSON(rw, http.StatusOK, map[string]interface{}{
		"status":  requests.StatusUpdated,
		"project": currentProject,
	})
}

// updateCollaboratorByProjectID creates/updates a collaborator for a
// specific project.
func updateCollaboratorByProjectIDHandler(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	projectID := vars["id"]

	var body schemas.Collaborator
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&body)
	if err != nil {
		requests.ErrorJSON(rw, http.StatusBadRequest, requests.StatusFailed, err.Error())
		return
	}

	// Get project.
	project, err := getProject(projectID)
	if err != nil {
		requests.ErrorJSON(rw, http.StatusBadRequest, requests.StatusFailed, err.Error())
		return
	}

	// Create/update entry for collaborator in project.
	// The only fields that can currently be updated are
	// name and email.
	isNewCollaborator := true
	if len(project.Collaborators) > 0 {
		for i, c := range project.Collaborators {
			if c.MACAddr == body.MACAddr {
				project.Collaborators[i].Name = body.Name
				project.Collaborators[i].Email = body.Email
				project.Collaborators[i].UpdatedAt = time.Now()
				isNewCollaborator = false
				break
			}
		}
	}

	if isNewCollaborator {
		body.ID = uuid.New()
		body.UpdatedAt = time.Now()
		body.Permissions = map[string]bool{}
		project.Collaborators = append(project.Collaborators, body)
	}

	// If this is a new project, assign the CreatorID as
	// the requesting collaborator.
	if isNewCollaborator && len(project.Collaborators) == 1 {
		project.CreatorID = body.ID
	}

	err = db.Set(schemas.ProjectsCollection, project.ID, project)
	if err != nil {
		requests.ErrorJSON(rw, http.StatusInternalServerError, requests.StatusFailed, err.Error())
	}

	renderer.JSON(rw, http.StatusOK, map[string]interface{}{
		"status":       requests.StatusUpdated,
		"collaborator": body,
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
		requests.ErrorJSON(rw, http.StatusBadRequest, requests.StatusFailed, err.Error())
		return
	}

	imageID := body.ImageID
	if imageID == "" {
		imageID = uuid.New()
	}

	// Locate project. If it can't be found, create a new one.
	var project *schemas.Project
	project, err = getProject(imageID)
	if err != nil {
		project = &schemas.Project{
			ID:            imageID,
			CreatedAt:     time.Now(),
			Licenses:      0,
			Collaborators: []schemas.Collaborator{},
		}
		err = db.Set(schemas.ProjectsCollection, project.ID, project)
		if err != nil {
			requests.ErrorJSON(rw, http.StatusInternalServerError, requests.StatusFailed, err.Error())
		}
	}

	slackC.SendMessage("#usage", "New container created for project: " + project.ID, "bowery police")

	container := &schemas.Container{
		ID:        uuid.New(),
		ImageID:   project.ID,
		LocalPath: body.LocalPath,
		CreatedAt: time.Now(),
	}

	// Get the instance to use from Google Cloud.
	if env != "testing" {
		instance, err := usePseudoRandomInstance(container.ImageID)
		if err != nil {
			data, _ := json.Marshal(map[string]string{"error": err.Error()})
			go pusherC.Publish(string(data), "error", fmt.Sprintf("container-%s", container.ID))
			requests.ErrorJSON(rw, http.StatusInternalServerError, requests.StatusFailed, err.Error())
			return
		}

		// Add this image to the instance.
		instance.Images = util.AppendUniqueStr(instance.Images, imageID)

		container.Instance = instance
		container.Address = instance.Address
	}

	err = db.Set(schemas.ContainersCollection, container.ID, container)
	if err != nil {
		requests.ErrorJSON(rw, http.StatusInternalServerError, requests.StatusFailed, err.Error())
		return
	}

	// In a separate routine, reset the agent, launch the appropriate
	// container via the Docker remote api, and update Orchestrate with the
	// new information.
	if env != "testing" {
		go func() {
			start := time.Now()
			go pusherC.Publish("environment:0", "progress", fmt.Sprintf("container-%s", container.ID))

			err := delancey.Create(container, body.Dockerfile)
			if err != nil {
				data, _ := json.Marshal(map[string]string{"error": err.Error()})
				go pusherC.Publish(string(data), "error", fmt.Sprintf("container-%s", container.ID))
				return
			}
			go pusherC.Publish("environment:1", "progress", fmt.Sprintf("container-%s", container.ID))
			elapsed := float64(time.Since(start).Nanoseconds() / 1000000)
			go stathat.PostEZValue("kenmare delancey create container time", config.StatHatKey, elapsed)

			start = time.Now()
			err = db.Set(schemas.ContainersCollection, container.ID, container)
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
		requests.ErrorJSON(rw, http.StatusBadRequest, requests.StatusFailed, err.Error())
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
		requests.ErrorJSON(rw, http.StatusBadRequest, requests.StatusFailed, err.Error())
		return
	}

	// Check project and collaborator settings to make sure
	// the requesting collaborator has rights to save.
	project, err := getProject(container.ImageID)
	if err != nil {
		requests.ErrorJSON(rw, http.StatusBadRequest, requests.StatusFailed, err.Error())
		return
	}

	macAddr := req.URL.Query().Get("mac_addr")

	canSave := false
	isCreator := false
	for _, c := range project.Collaborators {
		if c.MACAddr == macAddr {
			if c.ID == project.CreatorID {
				isCreator = true
			}

			if c.Permissions["canEdit"] {
				canSave = true
			}
		}
	}

	// If the requesting collaborator is not the creator and
	// can't save, deny save. If they are the creator skip
	// or if they can save skip. The last component is temporary,
	// it's meant to exist for users of old versions of the application
	// which don't set a creator id.
	if !isCreator && !canSave && project.CreatorID != "" {
		requests.ErrorJSON(rw, http.StatusBadRequest, requests.StatusFailed, "insufficient permissions")
		return
	}

	if env != "testing" {
		go func() {
			go pusherC.Publish("environment:0", "progress", fmt.Sprintf("container-%s", container.ID))
			err := delancey.Save(container)
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
		requests.ErrorJSON(rw, http.StatusBadRequest, requests.StatusFailed, err.Error())
		return
	}

	// In separate routines, reset the agent and recycle the instance.
	if env != "testing" {
		go func() {
			start := time.Now()
			log.Println("calling delancey delete")
			err := delancey.Delete(container)
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
			err = db.Set(schemas.InstancesCollection, container.Instance.ID, container.Instance)
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
		requests.ErrorJSON(rw, http.StatusInternalServerError, requests.StatusFailed, err.Error())
		return
	}
	var buf bytes.Buffer

	err = t.Execute(&buf, map[string]string{
		"Host":    config.ExportAddr,
		"ImageID": imageID,
	})
	if err != nil {
		requests.ErrorJSON(rw, http.StatusInternalServerError, requests.StatusFailed, err.Error())
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

func getProject(id string) (*schemas.Project, error) {
	project := new(schemas.Project)
	err := db.Get(schemas.ProjectsCollection, id, project)
	if err != nil {
		return nil, err
	}

	return project, nil
}

// getContainer retrieves a container from Orchestrate.
func getContainer(id string) (*schemas.Container, error) {
	container := new(schemas.Container)
	err := db.Get(schemas.ContainersCollection, id, container)
	if err != nil {
		return nil, err
	}

	return container, nil
}

func getInstances() ([]*schemas.Instance, error) {
	results, err := db.List(schemas.InstancesCollection)
	if err != nil {
		return nil, err
	}

	instances := make([]*schemas.Instance, len(results))
	for i, instance := range results {
		err = json.Unmarshal([]byte(instance.(string)), &instances[i])
		if err != nil {
			return nil, err
		}
	}

	return instances, nil
}

// useRandomInstance retrieves an instance to use removing it from the
// instances collection.
func usePseudoRandomInstance(imageID string) (*schemas.Instance, error) {
	instances, err := getInstances()
	if err != nil {
		return nil, err
	}

	// If none exist, some will be created by the cron job.
	if len(instances) <= 0 {
		return nil, kenmare.ErrNoInstances
	}

	var instance *schemas.Instance

	// Attempt to find an instance that has run that image before.
	if imageID != "" {
		for _, i := range instances {
			if _, isInSlice := util.StringInSlice(i.Images, imageID); isInSlice {
				instance = i
				break
			}
		}
	}

	if instance == nil {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(instances))))
		if err != nil {
			return nil, err
		}

		instance = instances[idx.Int64()]
	}

	// Delete the instance from the collection so it can't be used.
	err = db.Delete(schemas.InstancesCollection, instance.ID)
	if err != nil {
		return nil, err
	}

	return instance, nil
}
