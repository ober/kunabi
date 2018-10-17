#!/usr/bin/env gxi
;; -*- Gerbil -*-

(import :std/make)

(def build-spec
  '("proto"
    (exe: "kunabi"
	  "-cc-options" "-I/usr/local/Cellar/openssl/1.0.2o_2/include -I/usr/local/Cellar/mysql/5.7.22/include -I/usr/local/Cellar/libyaml/0.1.7/include -I/usr/local/Cellar/leveldb/1.20_2/include -I/usr/local/Cellar/lmdb/0.9.22/include"
	  "-ld-options" "-L/usr/local/Cellar/openssl/1.0.2o_2/lib -L/usr/local/Cellar/mysql/5.7.22/lib -L/usr/local/Cellar/libyaml/0.1.7/lib -L/usr/local/Cellar/leveldb/1.20_2/lib -L/usr/local/Cellar/lmdb/0.9.22/lib -lleveldb -lz -llmdb -lssl -lyaml"
	  "-prelude" "(declare (not safe))")))



(def build-spec-static
  '("proto"
    (static-exe: "kunabi"
		 "-cc-options" "-I/usr/local/Cellar/openssl/1.0.2o_2/include -I/usr/local/Cellar/mysql/5.7.22/include -I/usr/local/Cellar/libyaml/0.1.7/include -I/usr/local/Cellar/leveldb/1.20_2/include -I/usr/local/Cellar/lmdb/0.9.22/include"
		 "-ld-options" "-L/usr/local/Cellar/openssl/1.0.2o_2/lib -L/usr/local/Cellar/mysql/5.7.22/lib -L/usr/local/Cellar/libyaml/0.1.7/lib -L/usr/local/Cellar/leveldb/1.20_2/lib -L/usr/local/Cellar/lmdb/0.9.22/lib -lleveldb -lz -llmdb -lssl -lyaml"
                 "-prelude" "(declare (not safe))")))

(def srcdir
  (path-normalize (path-directory (this-source-file))))

(def (main . args)
  (match args
    (["deps"]
     (let (build-deps (make-depgraph/spec build-spec))
       (call-with-output-file "build-deps" (cut write build-deps <>))))
    (["static"]
     (let (depgraph (call-with-input-file "build-deps" read))
       (make srcdir: srcdir
             bindir: srcdir
             optimize: #t
             static: #t
             depgraph: depgraph
             prefix: "datadog"
             build-spec-static)))
    ([]
     (let (depgraph (call-with-input-file "build-deps" read))
       (make srcdir: srcdir
             bindir: srcdir
             optimize: #t
             debug: 'env
             static: #t
             depgraph: depgraph
             prefix: "datadog"
             build-spec)))))
