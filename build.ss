#!/usr/bin/env gxi
;; -*- Gerbil -*-

(import :std/build-script)

(defbuild-script
  `("kunabi/client"
    (static-exe:
     "kunabi/kunabi")))
