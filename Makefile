PROJECT := kunabi

DOCKER_IMAGE := "gerbil/alpine:amd64"

$(eval uid := $(shell id -u))
$(eval gid := $(shell id -g))

default: linux-static-docker

deps:
	/usr/bin/time -avp $(GERBIL_HOME)/bin/gxpkg install github.com/ober/oberlib
	/usr/bin/time -avp $(GERBIL_HOME)/bin/gxpkg install github.com/yanndegat/colorstring

build: deps
	$(GERBIL_HOME)/bin/gxpkg link $(PROJECT) /src || true
	$(GERBIL_HOME)/bin/gxpkg build $(PROJECT)

linux-static-docker:
	docker run -it \
	-e GERBIL_PATH=/src/.gerbil \
	-u "$(UID):$(GID)" \
    -v $(PWD):/src:z \
	$(DOCKER_IMAGE) \
	make -C /src linux-static

linux-static: build
	/usr/bin/time -avp $(GERBIL_HOME)/bin/gxc -o $(PROJECT)-bin -static -O \
	-cc-options "-Bstatic" \
	-ld-options "-static -lpthread -L/usr/lib/x86_64-linux-gnu -lleveldb -lssl -ldl -lyaml -lz -lstdc++" \
	-prelude "(declare (not safe))" \
	-exe $(PROJECT)/$(PROJECT).ss

clean:
	rm -Rf $(PROJECT)-bin

install:
	mv $(PROJECT)-bin /usr/local/bin/$(PROJECT)
