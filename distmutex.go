// Copyright 2014 Bowery, Inc.

// BUG(r-medina): Subscriptions to pusher events seems to only work one time.

package main

import (
	"encoding/json"
	"io"

	dm "github.com/Bowery/gopackages/distmutex"
	"github.com/Bowery/gorc"
	pusherSub "github.com/oguzbilgic/pusher"
	pusherPub "github.com/timonv/pusher"
)

const (
	unlockEvent = "unlock" // the string label for the unlock event
)

// OrcMutexDB implements the distmutex.MutexDB interface with an Orchestrate.io
// backend. Everything stored in this struct is necessary to use Orchestrate.
type OrcMutexDB struct {
	client     *gorc.Client
	collection string // name of collection in orchestrate
	key        string
	patchSet   gorc.PatchSet // for patching the collection
}

// NewOrcMutexDB is a simple constructor that sets the appropriate attributes for an `OrcMutexDB`
func NewOrcMutexDB(client *gorc.Client, collection, key string) *OrcMutexDB {
	return &OrcMutexDB{
		client:     client,
		collection: collection,
		key:        key,
	}
}

func (db *OrcMutexDB) Get(mutex *dm.Mutex) (bool, error) {
	v, err := db.client.Get(db.collection, db.key)
	if err != nil {
		oerr, ok := err.(*gorc.OrchestrateError)
		if !ok || oerr.StatusCode != 404 { // don't want to import http
			return false, err
		}

		return false, nil
	}

	return true, v.Value(mutex)
}

func (db *OrcMutexDB) Put(mutex *dm.Mutex) error {
	_, err := db.client.Put(db.collection, db.key, mutex)
	return err
}

func (db *OrcMutexDB) Patch() error {
	_, err := db.client.Patch(db.collection, db.key, db.patchSet)
	return err
}

func (db *OrcMutexDB) ResetPatch() {
	db.patchSet.Reset()
}

func (db *OrcMutexDB) SetWriting(isWriting bool) {
	db.patchSet.Replace("writing", isWriting)
}

func (db *OrcMutexDB) IncReaders(i float64) {
	db.patchSet.Inc("readers", i)
}

func (db *OrcMutexDB) IncQueuedWriters(i float64) {
	db.patchSet.Inc("queuedWriters", i)
}

func (db *OrcMutexDB) IncQueuedReaders(i float64) {
	db.patchSet.Inc("queuedReaders", i)
}

// PusherMutexWait implementsteh distmutex.MutexWait interface. The two functional
// attributes are created with the `NewPusherMutexWait` function which closes over values
// it's passed in order to not save any state other than the `Pub` and `Sub` functions. A
// `PusherMutexWait` wait should never be instantiated without the provided
// `NewPusherMutexWait` function.
type PusherMutexWait struct {
	// Sub returns a channel on which to listen for Pusher broadcasts
	Sub func() chan interface{}

	// Pub takes byte slice and broadcasts it using Pusher.
	Pub func([]byte) error

	// Closer is closed when an http request is cancelled. This is useful for decrementing
	// the queued counters.
	Closer chan struct{}
}

// NewPusherMutexWait takes the values it is passed and closes over them to create two
// functions, `Pub` and `Sub`, such that it is unnessary to save any more state to get the
// functionality of the `distmutes.MutexWait` interface.
func NewPusherMutexWait(
	channel string, sub *pusherSub.Channel, pub *pusherPub.Client,
) *PusherMutexWait {
	return &PusherMutexWait{
		Closer: make(chan struct{}),
		Sub: func() chan interface{} {
			return sub.Bind(unlockEvent)
		},
		Pub: func(data []byte) error {
			return pub.Publish(string(data), unlockEvent, channel)
		},
	}
}

func (w *PusherMutexWait) GetLock(mutex *dm.Mutex) error {
	ev := w.Sub()
	select {
	case <-w.Closer:
		return io.EOF
	case data := <-ev:
		buf := []byte(data.(string))

		return json.Unmarshal(buf, mutex)
	}
}

func (w *PusherMutexWait) ReleaseLock(mutex *dm.Mutex) error {
	data, err := json.Marshal(mutex)

	if err != nil {
		return err
	}

	return w.Pub(data)
}
