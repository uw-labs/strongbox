FROM golang:1.15-alpine

RUN apk --no-cache add git

ENV GOPATH=/go CGO_ENABLED=0
COPY . /go/src/github.com/uw-labs/strongbox
WORKDIR /go/src/github.com/uw-labs/strongbox

ENTRYPOINT ["/bin/sh", "/go/src/github.com/uw-labs/strongbox/integration_tests/run.sh"]
