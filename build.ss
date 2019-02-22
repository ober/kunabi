#!/usr/bin/env gxi
;; -*- Gerbil -*-

(import :std/make)
(import :std/format)

(def build-spec
  '("kunabi"
    (exe: "kunabi"
		 "-cc-options" "-I/usr/local/opt/leveldb/include -I/usr/local/include"
                 "-ld-options" "-lyaml  -lz -L/usr/local/lib -lleveldb"
		 "-prelude" "(declare (not safe))")))

(def build-spec-static
  '("kunabi"
    (static-exe: "kunabi"
		 "-cc-options" "-I/usr/local/opt/leveldb/include -I/usr/local/include"
                 "-ld-options" "-lyaml -lssl -lz -L/usr/local/lib -lleveldb"
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
