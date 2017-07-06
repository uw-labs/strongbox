export CGO_ENABLED=0

export USER=test
export HOME=/home/test

go get -t .
go test
