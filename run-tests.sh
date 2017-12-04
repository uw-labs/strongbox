export CGO_ENABLED=0

export USER=${USER:-test}
export PATH=$PATH:`pwd`:$GOPATH/bin

go get -t .
go install

go get -t ./int_tests/
go test ./int_tests/
