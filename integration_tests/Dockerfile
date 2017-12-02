FROM alpine:3.7

RUN apk --no-cache add git go musl-dev

ENV GOPATH /go
COPY . /go/src/github.com/uw-labs/strongbox
WORKDIR /go/src/github.com/uw-labs/strongbox

ENTRYPOINT ["/bin/sh", "/go/src/github.com/uw-labs/strongbox/integration_tests/run.sh"]
