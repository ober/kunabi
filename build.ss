#!/usr/bin/env gxi
;; -*- Gerbil -*-

(import :std/build-script)

(defbuild-script
  `("kunabi/cloudtrail"
    (static-exe:
     "kunabi/main"
     bin: "kunabi"
     "-ld-options"
     "-lpthread -lleveldb -lyaml -ldl -lssl -lz -L/usr/lib64")))
