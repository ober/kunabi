default: kunabi

SYSTEM := $(shell uname -s)

ifeq ($(SYSTEM),Darwin)
SSL-BASE :=$(lastword $(wildcard /usr/local/Cellar/openssl/*/))
SED := sed
MYSQL-BASE := $(lastword $(wildcard /usr/local/Cellar/mysql/*/))
LEVELDB-BASE := $(lastword $(wildcard /usr/local/Cellar/leveldb/*/))
LMDB-BASE := $(lastword $(wildcard /usr/local/Cellar/lmdb/*/))
LIBYAML-BASE := $(lastword $(wildcard /usr/local/Cellar/libyaml/*/))
$(eval LDFLAGS := "-L$(SSL-BASE)lib -L$(MYSQL-BASE)lib -L$(LIBYAML-BASE)lib -L$(LEVELDB-BASE)lib -L$(LMDB-BASE)lib -lleveldb -lz -llmdb -lssl -lyaml -L/usr/local/lib")
$(eval CPPFLAGS := "-I$(SSL-BASE)include -I$(MYSQL-BASE)include -I$(LIBYAML-BASE)include -I$(LEVELDB-BASE)include -I$(LMDB-BASE)include -I/usr/local/include")
else
LDFLAGS := "-L/usr/lib -lssl -lyaml"
CPPFLAGS := "-I/usr/include"
LIBYAML-BASE := "/usr/include"
SED := sed
endif

$(info $(CPPFLAGS) is cppflags)
$(info $(LDFLAGS) is ldflags)

kunabi: $(eval CPPFLAGS := "-I$(SSL-BASE)include -I$(MYSQL-BASE)include -I$(LIBYAML-BASE)include -I$(LEVELDB-BASE)include -I$(LMDB-BASE)include -I/usr/local/include")
kunabi: $(eval LDFLAGS := "-L$(SSL-BASE)lib -L$(MYSQL-BASE)lib -L$(LIBYAML-BASE)lib -L$(LEVELDB-BASE)lib -L$(LMDB-BASE)lib -lleveldb -lz -llmdb -lssl -lyaml -L/usr/local/lib")
kunabi:
	./build.ss
