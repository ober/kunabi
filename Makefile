PROJECT := kunabi

ARCH := $(shell uname -m)
DOCKER_IMAGE := "gerbil/gerbilxx:$(ARCH)-master"
UID := $(shell id -u)
GID := $(shell id -g)
PWD := $(shell pwd)

default: linux-static-docker

deps:
	/opt/gerbil/bin/gxpkg deps -i

build: deps
	git config --global --add safe.directory /src
	/opt/gerbil/bin/gxpkg link $(PROJECT) /src || true
	/opt/gerbil/bin/gxpkg build -R $(PROJECT)

linux-static-docker: clean
	docker run -it \
	-e GERBIL_PATH=/src/.gerbil \
	-e USER=$(USER) \
	-u "$(UID):$(GID)" \
	-e UID=$(UID) \
	-e GID=$(GID) \
	-v $(PWD):/src:Z \
	$(DOCKER_IMAGE) \
	make -C /src build

clean:
	rm -rf .gerbil

install:
	mv .gerbil/bin/$(PROJECT) /usr/local/bin/$(PROJECT)
