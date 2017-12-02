export CGO_ENABLED=0

export USER=test
export HOME=/home/${USER}
mkdir ${HOME}

export PATH=${PATH}:${GOPATH}/bin

go get -t .
go install

go get -t ./integration_tests/
go test -v ./integration_tests/
