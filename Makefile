BINARY  := mcastwatch
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := CGO_ENABLED=0

ARCHES := amd64 arm64 arm

.PHONY: all
all: test build

.PHONY: build
build:
	$(GOFLAGS) go build -ldflags="$(LDFLAGS)" -o $(BINARY) .

.PHONY: test
test:
	go test -race ./...

.PHONY: check
check:
	@test -z "$$(gofmt -l .)" || { echo "needs gofmt:"; gofmt -l .; exit 1; }
	go vet ./...

.PHONY: dist
dist: $(addprefix dist/,$(ARCHES))

dist/%:
	@mkdir -p dist
	$(GOFLAGS) GOOS=linux GOARCH=$* $(if $(filter arm,$*),GOARM=6,) \
		go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-$* .
	@cd dist && tar czf $(BINARY)-$(VERSION)-linux-$*.tar.gz \
		$(BINARY)-linux-$* -C .. mcastwatch@.service README.md
	@echo "built dist/$(BINARY)-$(VERSION)-linux-$*.tar.gz"

.PHONY: install
install: build
	install -m 0755 $(BINARY) /usr/local/bin/$(BINARY)
	install -m 0644 mcastwatch@.service /etc/systemd/system/
	systemctl daemon-reload
	@echo "installed. start with: systemctl enable --now mcastwatch@<iface>"

.PHONY: uninstall
uninstall:
	-systemctl disable --now 'mcastwatch@*'
	rm -f /usr/local/bin/$(BINARY) /etc/systemd/system/mcastwatch@.service
	systemctl daemon-reload

.PHONY: clean
clean:
	rm -rf $(BINARY) dist
