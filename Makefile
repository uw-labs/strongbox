IMAGE=strongbox-test

documentation:
	cd docs/src && hugo -b https://uw-labs.github.io/strongbox/

build-test-image:
	docker build -t $(IMAGE) -f Dockerfile.test .

test: build-test-image
	docker run $(IMAGE)
