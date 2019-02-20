#!/usr/bin/env gxi
;; -*- Gerbil -*-

(import :std/make)

(def lmdb-ver "0.9.23")
(def mysql-ver "8.0.15")
(def ssl-ver "1.0.2q")
(def yaml-ver "0.2.1")
(def leveldb-ver "1.20_2")

(def build-spec
  '("proto"
    (exe: "kunabi"
	  "-cc-options"
	  (format "-I/usr/local/Cellar/openssl/~a/include -I/usr/local/Cellar/mysql/~a/include -I/usr/local/Cellar/libyaml/~a/include -I/usr/local/Cellar/leveldb/~a/include -I/usr/local/Cellar/lmdb/~a/include" ssl-ver mysql-ver yaml-ver leveldb-ver lmdb-ver)
	  "-ld-options"
	  (format "-L/usr/local/Cellar/openssl/~a/lib -L/usr/local/Cellar/mysql/~a/lib -L/usr/local/Cellar/libyaml/~a/lib -L/usr/local/Cellar/leveldb/~a/lib -L/usr/local/Cellar/lmdb/~a/lib -lleveldb -lz -llmdb -lssl -lyaml" ssl-ver mysql-ver yaml-ver leveldb-ver lmdb-ver)
	  "-prelude" "(declare (not safe))")))

(def build-spec-static
  '("proto"
    (static-exe: "kunabi"
		 "-cc-options"
		 (format "-I/usr/local/Cellar/openssl/~a/include -I/usr/local/Cellar/mysql/~a/include -I/usr/local/Cellar/libyaml/~a/include -I/usr/local/Cellar/leveldb/~a/include -I/usr/local/Cellar/lmdb/~a/include" ssl-ver mysql-ver yaml-ver leveldb-ver lmdb-ver)
		 "-ld-options"
		 (format "-L/usr/local/Cellar/openssl/~a/lib -L/usr/local/Cellar/mysql/~a/lib -L/usr/local/Cellar/libyaml/~a/lib -L/usr/local/Cellar/leveldb/~a/lib -L/usr/local/Cellar/lmdb/~a/lib -lleveldb -lz -llmdb -lssl -lyaml" ssl-ver mysql-ver yaml-ver leveldb-ver lmdb-ver)
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
