# kenmare

Bowery Environment Manager.

## About

Kenmare is responsible for creating and managing development environments, and keeping track of events that occur in them.
It is able to spin up instances on EC2, and will eventually be able to assist in reconstructing an environment
using the events it keeps track of.

Kenmare uses Orchestrate.io as a datastore.

## Routes

### `POST /applications`

Create a new application and associated environment. If the request includes an environment identifier, replicate that environment. Note: that functionality does not exist yet

**Required params:** `ami`, `instance_type`, `aws_access_key`, `aws_secret_key`, `token`.

**Optional params:** `envID`, `ports`.

### `GET /applications?token={token}`

Get all applications owned by the user with the specified token.

### `GET /applications/{id}`

Get an application by id.

### `DELETE /applications/{id}?token={token}`

Delete an application by id owned by the user with the specified token.

### `GET /environments/{id}`

Get an environment and associated events.

### `POST /events`

Create an event.

**Required params:** `type`, `body`, `envID`.
