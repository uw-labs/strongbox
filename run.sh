export CGO_ENABLED=0

export USER=test
export HOME=/home/${USER}
mkdir ${HOME}

export PATH=${PATH}:${GOPATH}/bin

go get -t .
go install

go get -t ./int_tests/
go test -v ./int_tests/
