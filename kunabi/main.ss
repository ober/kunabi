;;; -*- Gerbil -*-
;;; © ober
;;; AWS Cloudwatch parser library

(import
  :gerbil/gambit
  :gerbil/gambit/os
  :gerbil/gambit/threads
  :std/db/leveldb
  :std/debug/heap
  :std/debug/memleak
  :std/format
  :std/generic/dispatch
  :std/iter
  :std/misc/list
  :std/pregexp
  :std/srfi/1
  :std/srfi/95
  :std/sugar
  :std/text/json
  :std/text/yaml
  :std/text/zlib
  :ober/oberlib
  :ober/kunabi/cloudtrail
;;  :ober/kunabi/vpc
  )

(declare (not optimize-dead-definitions))
(export main)

(def program-name "kunabi")

(def interactives
  (hash
   ("ct" (hash (description: "ct <directory> => Load all files in dir. ") (usage: "") (count: 1)))
   ("compact" (hash (description: "Compact ") (usage: "compact") (count: 0)))
   ("countdb" (hash (description: "Count how many db entries there are ") (usage: "count") (count: 0)))
   ("count-key" (hash (description: "Count how many db entries there are for key ") (usage: "count-key <key>") (count: 1)))
   ("match-key" (hash (description: "Count how many db entries there are for key ") (usage: "match-key <key>") (count: 1)))
   ("le" (hash (description: "List all event names. ") (usage: "le") (count: 0)))
   ("lec" (hash (description: "lec => List all Error Codes") (usage: "lec") (count: 0)))
   ("lip" (hash (description: "lip => List all source ips") (usage: "lip") (count: 0)))
   ("ln" (hash (description: "ln => List all user names. ") (usage: "ln") (count: 0)))
   ("lr" (hash (description: "lr => List all Regions") (usage: "lr") (count: 0)))
   ("ls" (hash (description: "ls => list all records") (usage: "ls") (count: 0)))
   ("lsv" (hash (description: "lsv => list all vpc records") (usage: "lsv") (count: 0)))
   ("read" (hash (description: "read <file> => read in ct file") (usage: "read <file>") (count: 1)))
   ("se" (hash (description: "se <event name> => list all records of type event name") (usage: "read <file>") (count: 1)))
   ("sec" (hash (description: "sec <error coded> => list all records of error code") (usage: "sec <error code>") (count: 1)))
   ("sip" (hash (description: "sip <ip address> => list all records from ip address") (usage: "sip <ip address>") (count: 1)))
   ("sn" (hash (description: "sn <user name> => list all records for user name") (usage: "sn <username>") (count: 1)))
   ("sr" (hash (description: "sr <Region name> => list all records for region name") (usage: "sr <region name>") (count: 1)))
   ("st" (hash (description: "st: Status") (usage: "sr") (count: 0)))
   ("repairdb" (hash (description: "repairdb") (usage: "repairdb") (count: 0)))
   ("report" (hash (description: "report") (usage: "report <username>") (count: 1)))
   ))

(def (main . args)
  (if (null? args)
    (usage))
  (let* ((argc (length args))
	 (verb (car args))
	 (args2 (cdr args)))
    (unless (hash-key? interactives verb)
      (usage))
    (let* ((info (hash-get interactives verb))
	   (count (hash-get info count:)))
      (unless count
	(set! count 0))
      (unless (= (length args2) count)
	(usage-verb verb))
      (apply (eval (string->symbol (string-append "ober/kunabi/cloudtrail#" verb))) args2)))
  (when db (db-close))
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
