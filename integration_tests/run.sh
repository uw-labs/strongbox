export CGO_ENABLED=0

export USER=${USER:-root}
export PATH=$PATH:$GOPATH/bin

go get -t .
go install

go get -t ./integration_tests/
go test -v ./integration_tests/
