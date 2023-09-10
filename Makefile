PROJECT := kunabi

ARCH	     := $(shell uname)
DOCKER_IMAGE := "gerbil/alpine:$(ARCH)"

default: linux-static-docker

deps:
	/opt/gerbil/bin/gxpkg install github.com/ober/oberlib

build: deps
	/opt/gerbil/bin/gxpkg link $(PROJECT) /src || true
	/opt/gerbil/bin/gxpkg build $(PROJECT)

linux-static-docker:
	docker run -it \
	-e GERBIL_PATH=/src/.gerbil \
	-v $(PWD):/src:Z \
	$(DOCKER_IMAGE) \
	make -C /src build

linux-static: build
	/opt/gerbil/bin/gxc -o $(PROJECT)-bin -static  -O \
	-cc-options "-Bstatic" \
	-ld-options "-static -lpthread -lleveldb -lyaml -lz" \
	-exe $(PROJECT)/main.ss

clean:
	rm -f $(PROJECT)-bin

install:
	mv $(PROJECT)-bin /usr/local/bin/$(PROJECT)
