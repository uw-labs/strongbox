#!/bin/sh

PATH=$PATH:$GOPATH/bin

go get -t .
go install

go get -t ./integration_tests/
go test -v -tags=integration ./integration_tests/
