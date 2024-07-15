IMAGE=strongbox-test

.DEFAULT_GOAL := test

build-test-image:
	docker build -t $(IMAGE) -f Dockerfile .

test: build-test-image
	docker run --tmpfs /root:rw --rm $(IMAGE)
