;;; -*- Gerbil -*-
;;; © ober
;;; AWS Cloudwatch parser library

(import
  :clan/db/leveldb
  :gerbil/gambit
  :ober/kunabi/cloudtrail
  :ober/oberlib
  :std/actor
  :std/db/dbi
  :std/db/postgresql
  :std/db/postgresql-driver
  :std/getopt
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
    (command 'compact help: "Compact"))

  (def countdb
    (command 'countdb help: "Count how many db entries there are "))
  (def le
    (command 'le help: "List all event names. "))
  (def lec
    (command 'lec help: "List all Error Codes"))
  ;; (def lip
  ;;   (command 'lip help: "List all source ips"))
  (def ln
    (command 'ln help: "List all user names. "))
  ;; (def lr
  ;;   (command 'lr help: "List all Regions"))
  (def ls
    (command 'ls help: "list all records"))
  ;; (def lsv
  ;;   (command 'lsv help: "list all vpc records"))
  (def read
    (command 'read help: "read in ct file"
	     (argument 'file)))
  (def se
    (command 'se help: "Search for event name"
	     (argument 'event)))
  (def sec
    (command 'sec help: "list all records of error code"
	     (argument 'event)))
  ;; (def sip
  ;;   (command 'sip help: "list all records from ip address"
  ;; 	     (argument 'event help: "Ip address")))
  (def sn
    (command 'sn help: "list all records for user name"
	     (argument 'event help: "username")))
  ;; (def sr
  ;;   (command 'sr help: "list all records for region name"
  ;; 	     (argument 'event help: "region")))
  (def st
    (command 'st help: "Show status"))
  (def repairdb
    (command 'repairdb help: "repairdb"))
  (def report
    (command 'report help: "report"
	     (argument 'user help: "username")))

  (call-with-getopt process-args args
		    program: "kunabi"
		    help: "Cloudtrail parser in Gerbil"
		    ct
		    compact
		    countdb
		    le
		    lec
;;		    lip
		    ln
;;		    lr
		    ls
;;		    lsv
		    read
		    repairdb
		    report
		    se
		    sec
;;		    sip
		    sn
;;		    sr
		    st))



(def (process-args cmd opt)
  (let-hash opt
    (case cmd
      ((ct)
       (ct .directory))
      ((compact)
       (compact))
      ((countdb)
       (countdb))
      ((le)
       (le))
      ((lec)
       (lec))
      ;; ((lip)
      ;;  (lip))
      ((ln)
       (ln))
      ;; ((lr)
      ;;  (lr))
      ((ls)
       (ls))
      ;; ((lsv)
      ;;  (lsv))
      ((read)
       (read .file))
      ((repairdb)
       (repairdb))
      ((report)
       (report .user))
      ((se)
       (se .event))
      ((sec)
       (sec .event))
      ;; ((sip)
      ;;  (sip .event))
      ((sn)
       (sn .event))
      ;; ((sr)
      ;;  (sr .event))
      ((st)
      (st)))))
