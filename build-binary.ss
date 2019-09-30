#!/usr/bin/env gxi
;; -*- Gerbil -*-

(import :std/build-script
        :std/format
	:std/make)

(def build-spec
  '("kunabi"
    (exe: "kunabi" "-ld-options" "-lyaml -lssl -lz -L/usr/local/opt/openssl/lib/ -L/usr/local/lib" "-cc-options" "-I/usr/local/opt/openssl/include -I/usr/local/include")
    ))

(def build-spec-static
  '("kunabi"
    (static-exe: "kunabi"
                 "-ld-options" "-lyaml -lssl -lz -L/usr/local/opt/openssl/lib -L/usr/local/lib"
		 "-cc-options" "-I/usr/local/opt/openssl/include -I/usr/local/include"
                 "-prelude" "(declare (not safe))")))

(def srcdir
  (path-normalize (format "~a/~a" (path-directory (this-source-file)) "kunabi")))

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
             prefix: "kunabi"
             build-spec-static)))
    ([]
     (let (depgraph (call-with-input-file "build-deps" read))
       (make srcdir: srcdir
             bindir: srcdir
             optimize: #t
             debug: #t
             static: #t
             depgraph: depgraph
             prefix: "kunabi"
             build-spec)))))
