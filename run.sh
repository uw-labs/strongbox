export CGO_ENABLED=0

export USER=test
export HOME=/home/test
mkdir $HOME

export PATH=$PATH:$GOPATH/bin

go get -t .
go install

go get -t ./int_tests/
go test ./int_tests/
