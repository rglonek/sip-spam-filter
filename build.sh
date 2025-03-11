#!/bin/bash

rm -rf sip-spam-filter bin
set -e
mkdir sip-spam-filter
mkdir sip-spam-filter/blacklists/
mkdir bin
cp config.yaml sip-spam-filter/
cp blacklist.txt sip-spam-filter/blacklists/

export CGO_ENABLED=0
export COPYFILE_DISABLE=1
export GOWORK=off

GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o sip-spam-filter/sip-spam-filter main.go && chmod +x sip-spam-filter/sip-spam-filter
tar --no-xattrs --no-acls -zcvf bin/sip-spam-filter-linux-amd64.tar.gz sip-spam-filter

GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o sip-spam-filter/sip-spam-filter main.go && chmod +x sip-spam-filter/sip-spam-filter
tar --no-xattrs --no-acls -zcvf bin/sip-spam-filter-linux-arm64.tar.gz sip-spam-filter

GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o sip-spam-filter/sip-spam-filter main.go && chmod +x sip-spam-filter/sip-spam-filter
tar --no-xattrs --no-acls -zcvf bin/sip-spam-filter-darwin-amd64.tar.gz sip-spam-filter

GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o sip-spam-filter/sip-spam-filter main.go && chmod +x sip-spam-filter/sip-spam-filter
tar --no-xattrs --no-acls -zcvf bin/sip-spam-filter-darwin-arm64.tar.gz sip-spam-filter

set +e
rm -rf sip-spam-filter
