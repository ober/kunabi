#!/usr/bin/env gxi
;; -*- Gerbil -*-

(import :std/build-script)

(defbuild-script
  `("kunabi/cloudtrail"
    (optimized-static-exe:
     "kunabi/main"
     bin: "kunabi"
     "-ld-options"
     "-lyaml -lleveldb -lstdc++ -lssl -lcrypto -lz -lm"
     )))
