# kenmare

Kenmare is responsible for the lifecycle of an environment. From creation, to update, to termination, Kenmare takes care of it.

## Prerequisites

Kenmare relies on [etcd](https://github.com/coreos/etcd) as a datastore.

## Development

The kenmare server listens on port 3000 in development and can be started by running:

```
$ make
```

## Tests

```
$ make test
```

## Formatting

Bowery's packages are formatted via [gofmt](https://golang.org/cmd/gofmt/) and linted via [golint](https://github.com/golang/lint).

You can install these tools by running

```
$ make deps
```

And you can format and lint by running

```
$ make format
```

## Integration

Kenmare comes bundled with some useful client methods for interacting with Kenmare, which can be found in `/kenmare`.

For example:

```go
import (
  "github.com/Bowery/kenmare/kenmare"
)

func main() {
  container, err := kenmare.CreateContainer("some-image-id", "/Users/chiefkeef/dev/website")
  if err != nil {
    t.Fatal(err)
  }

  log.Println(container.ID)
}
```
