#!/usr/bin/env gxi
;; -*- Gerbil -*-

(import :std/build-script)

(defbuild-script
  `("kunabi/cloudtrail"
    (exe:
     "kunabi/main"
     bin: "kunabi"
     "-ld-options"
     "-lpthread -lleveldb -lyaml -ldl -lz -L/usr/lib64")))
