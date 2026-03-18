# Contributing

Thanks for contributing. Keep changes focused and easy to review.

## Setup
```bash
go version
go mod download
```

## Run locally
```bash
WEBUI_PORT=8090 WEBUI_USER=admin WEBUI_PASSWORD=changeme go run ./cmd/server
```

## Code style
- Run `gofmt` on Go files.
- Keep UI changes small and test in the browser.

## Tests
There is no formal test suite yet. For now:
```bash
go test ./cmd/server
```

## Pull requests
- Describe the change and the reason.
- Mention any API or UI behavior changes.
