#!/usr/bin/env gxi
;; -*- Gerbil -*-

(import :std/build-script)

(defbuild-script
  `("kunabi/client"
    (exe:
     "kunabi/kunabi"
     "-ld-options"
     "-lyaml -lleveldb"
     )))
