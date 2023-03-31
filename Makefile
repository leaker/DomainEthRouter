.PHONY: all build copy-configs

all: build

build: copy-configs
	go build -ldflags "-s -w -H windowsgui" -o bin/DomainEthRouter.exe cmd/DomainEthRouter/main.go

copy-configs:
	cmd /c xcopy /D configs\* bin\
