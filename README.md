# kenmare

Kenmare is responsible for the lifecycle of an environment. From creation, to update, to termination, Kenmare takes care of it.

## Development

The kenmare server listens on port 3000 in development and can be started by running:

```
$ go get -d && go build -o kenmare-server && ./kenmare-server
```

## Tests

```
$ go test ./...
```

## Integration

Kenmare comes bundled with some useful client methods for interacting with Kenmare, which can be found in `/kenmare`.

For example:

```go
import (
  "github.com/Bowery/kenmare/kenmare"
)

func main() {
  container, err := kenmare.CreateContainer("some-image-id")
  if err != nil {
    t.Fatal(err)
  }

  log.Println(container.ID)
}
```
