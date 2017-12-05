IMAGE=strongbox-test

documentation:
	cd docs/src && hugo -b https://uw-labs.github.io/strongbox/

build-test-image:
	docker build -t $(IMAGE) -f integration_tests/Dockerfile .

test: build-test-image
	docker run --rm $(IMAGE) --tmpfs /root:rw
