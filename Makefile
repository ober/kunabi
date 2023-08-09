PROJECT := kunabi

DOCKER_IMAGE := "gerbil/fedora:smp-debugging"

$(eval UID := $(shell id -u))
$(eval GID := $(shell id -g))

default: linux-static-docker

deps:
	$(GERBIL_HOME)/bin/gxpkg install github.com/ober/oberlib
	$(GERBIL_HOME)/bin/gxpkg install github.com/yanndegat/colorstring

build: deps
	$(GERBIL_HOME)/bin/gxpkg link $(PROJECT) /src || true
	$(GERBIL_HOME)/bin/gxpkg build $(PROJECT)

linux-static-docker:
	docker run -it \
	-e GERBIL_PATH=/tmp/.gerbil \
    -v $(PWD):/src:Z \
	$(DOCKER_IMAGE) \
	make -C /src linux-static

linux-static: build
	$(GERBIL_HOME)/bin/gxc -o $(PROJECT)-bin -static -O \
	-cc-options "-Bstatic" \
	-ld-options "-static -lpthread -L/usr/lib64 -lleveldb -ldl -lyaml -lz -lstdc++" \
	-prelude "(declare (not safe))" \
	-exe $(PROJECT)/main.ss

clean:
	rm -Rf $(PROJECT)-bin

install:
	mv $(PROJECT)-bin /usr/local/bin/$(PROJECT)
