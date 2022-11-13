#!/usr/bin/env gxi
;; -*- Gerbil -*-

(import :std/build-script)

(defbuild-script
  `("kunabi/client"
    (exe:
     "kunabi/kunabi"
     "-ld-options"
     "-lpthread -lleveldb -lyaml -ldl -lssl -lz -L/usr/lib64 -L/usr/pkg/lib -I/usr/pkg/include"))
  verbose: 10)
