;;; -*- Gerbil -*-
;;; © ober
;;; AWS Cloudwatch parser library

(import
  :clan/db/leveldb
  :gerbil/gambit
  :ober/kunabi/client
  :ober/oberlib
  :std/actor
  :std/db/dbi
  :std/db/postgresql
  :std/db/postgresql-driver
  :std/debug/heap
  :std/debug/memleak
  :std/format
  :std/generic/dispatch
  :std/iter
  :std/logger
  :std/misc/list
  :std/misc/lru
  :std/net/address
  :std/net/httpd
  :std/pregexp
  :std/srfi/1
  :std/srfi/95
  :std/sugar
  :std/text/json
  :clan/text/yaml
  :std/text/zlib
  )

(export main)
(def program-name "kunabi")

(def (main . args)
  (def ct
    (command 'ct help: "Load all files in dir. "
	     (argument 'directory help: "Directory where the Cloudtrail files reside")))

  (def compact
    (command 'compact help: (hash "Compact")))

  (def countdb
    (command 'countdb help: "Count how many db entries there are "))
  (def le
    (command 'le help: "List all event names. "))
  (def lec
    (command 'lec help: "List all Error Codes"))
  (def lip
    (command 'lip help: "List all source ips"))
  (def ln
    (command 'ln help: "List all user names. "))
  (def lr
    (command 'lr help: "List all Regions"))
  (def ls
    (command 'ls help: "list all records"))
  (def lsv
    (command 'lsv help: "list all vpc records"))
  (def read
    (command 'read help: "read in ct file"
	     (argument 'file)))
  (def se
    (command 'se help: "Search for event name"
	     (command 'event help: "Event to search for")))
  ("sec" (hash (description: "sec <error coded> => list all records of error code") (usage: "sec <error code>") (count: 1)))
   ("sip" (hash (description: "sip <ip address> => list all records from ip address") (usage: "sip <ip address>") (count: 1)))
   ("sn" (hash (description: "sn <user name> => list all records for user name") (usage: "sn <username>") (count: 1)))
   ("sr" (hash (description: "sr <Region name> => list all records for region name") (usage: "sr <region name>") (count: 1)))
   ("st" (hash (description: "st: Status") (usage: "sr") (count: 0)))
   ("repairdb" (hash (description: "repairdb") (usage: "repairdb") (count: 0)))
   ("report" (hash (description: "report") (usage: "report") (count: 0)))
   ))

  (call-with-getopt process-args args
program: "kunabi"
help: "Cloudtrail parser in Gerbil"




  (db-close)
  )

(def (usage-verb verb)
  (let ((howto (hash-get interactives verb)))
    (displayln "Wrong number of arguments. Usage is:")
    (displayln program-name " " (hash-get howto usage:))
    (exit 2)))

(def (usage)
  (displayln (format "Kunabi: version ~a" version))
  (displayln "Usage: kunabi <verb>")
  (displayln "Verbs:")
  (for (verb (sort! (hash-keys interactives) string<?))
       (displayln (format "~a: ~a" verb (hash-get (hash-get interactives verb) description:))))
  (exit 2))
