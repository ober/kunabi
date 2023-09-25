PROJECT := kunabi

ARCH := $(shell uname -m)
DOCKER_IMAGE := "gerbil/gerbilxx:$(ARCH)"

default: linux-static-docker

deps:
	/opt/gerbil/bin/gxpkg install github.com/ober/oberlib
	/opt/gerbil/bin/gxpkg deps -i
	/opt/gerbil/bin/gxpkg install github.com/yanndegat/colorstring

build: deps
	/opt/gerbil/bin/gxpkg link $(PROJECT) /src || true
	/opt/gerbil/bin/gxpkg build -R $(PROJECT)

linux-static-docker: clean
	docker run -it \
	-e GERBIL_PATH=/src/.gerbil \
	-e USER=$(USER) \
	-v $(PWD):/src:z \
	$(DOCKER_IMAGE) \
	make -C /src build

clean:
	rm -rf .gerbil

install:
	mv ~/.gerbil/bin/$(PROJECT) /usr/local/bin/$(PROJECT)
