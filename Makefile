documentation:
	cd docs/src && hugo -b https://uw-labs.github.io/strongbox/

build-test-image:
	docker build -t strongbox-test-image -f integration_tests/Dockerfile .

test: build-test-image
	docker run --rm strongbox-test-image --tmpfs /home/test:rw
