IMAGE=strongbox-test

.DEFAULT_GOAL := test

build-test-image:
	docker build -t $(IMAGE) -f integration_tests/Dockerfile .

test: build-test-image
	docker run --tmpfs /root:rw --rm $(IMAGE)

bench:
	go test -bench=.

release:
	@sd "const version = \"dev\"" "const version = \"$(VERSION)\"" strongbox.go
	@git add -- strongbox.go
	@git commit -m "Release $(VERSION)"
	@sd "const version = \"$(VERSION)\"" "const version = \"dev\"" strongbox.go
	@git add -- strongbox.go
	@git commit -m "Clean up release $(VERSION)"
