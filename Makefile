.PHONY: all build

build:
	export CGO_ENABLED=0
	GOOS=linux GOARCH=amd64 go build -o bin/kube-ldap-client-purego-exec-plugin-linux-amd64
	GOOS=linux GOARCH=arm64 go build -o bin/kube-ldap-client-purego-exec-plugin-linux-arm64
	GOOS=darwin GOARCH=amd64 go build -o bin/kube-ldap-client-purego-exec-plugin-darwin-amd64
	GOOS=darwin GOARCH=arm64 go build -o bin/kube-ldap-client-purego-exec-plugin-darwin-arm64
	GOOS=windows GOARCH=amd64 go build -o bin/kube-ldap-client-purego-exec-plugin-windows-amd64.exe

all: build
