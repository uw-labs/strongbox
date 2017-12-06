#!/bin/sh

CGO_ENABLED=0
PATH=$PATH:$GOPATH/bin

go get -t .
go install

go get -t ./integration_tests/
go test -v ./integration_tests/
