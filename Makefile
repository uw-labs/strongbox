documentation:
	cd docs/src && hugo -b https://uw-labs.github.io/strongbox/

build-test-image:
	docker build -t sb-test-image -f Dockerfile.test .

test: build-test-image
	docker run sb-test-image
