PROJECT := kunabi
ARCH := $(shell uname -m)
PWD := $(shell pwd)
GERBIL_HOME := /opt/gerbil
DOCKER_IMAGE := "gerbil/gerbilxx:$(ARCH)-master"
UID := $(shell id -u)
GID := $(shell id -g)

default: linux-static-docker

check-root:
	@if [ "${UID}" -eq 0 ]; then \
	git config --global --add safe.directory /src; \
	fi

deps:
	$(GERBIL_HOME)/bin/gxpkg install github.com/mighty-gerbils/gerbil-libyaml
	$(GERBIL_HOME)/bin/gxpkg install github.com/ober/oberlib

build: deps check-root
	$(GERBIL_HOME)/bin/gxpkg link $(PROJECT) /src || true
	$(GERBIL_HOME)/bin/gxpkg build -R $(PROJECT)

linux-static-docker: clean
	docker run -t \
	-u "$(UID):$(GID)" \
	-v $(PWD):/src:z \
	$(DOCKER_IMAGE) \
	make -C /src build

clean:
	rm -rf .gerbil manifest.ss

install:
	mv .gerbil/bin/$(PROJECT) /usr/local/bin/$(PROJECT)
