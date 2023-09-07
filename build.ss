#!/usr/bin/env gxi
;; -*- Gerbil -*-

(import :std/build-script)

(defbuild-script
  `("kunabi/cloudtrail"
    (exe:
     "kunabi/main"
     bin: "kunabi")))
