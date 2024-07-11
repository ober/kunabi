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

     (def index
          (command 'index help: "Index user, errocode, events"))

     (def le
          (command 'le help: "List all event names. "))

     (def lec
          (command 'lec help: "List all Error Codes"))
     (def ln
          (command 'ln help: "List all user names. "))
     (def ls
          (command 'ls help: "list all records"))
     (def q
          (command 'q help: "run stored query"
                   (argument 'query help: "query")))

     (def read
          (command 'read help: "read in ct file"
	                 (argument 'file)))
     (def se
          (command 'se help: "Search for event name"
	                 (argument 'event)))
     (def sec
          (command 'sec help: "list all records of error code"
	                 (argument 'event)))
     (def maintenance
          (command 'maintenance help: "Do maintenance on db"))
     (def sn
          (command 'sn help: "list all records for user name"
	                 (argument 'event help: "username")))
     (def st
          (command 'st help: "Show status"))
     (def repairdb
          (command 'repairdb help: "repairdb"))

     (def db-copy
          (command 'db-copy help: "Copy all records from db1 to db2"
	                 (argument 'src help: "Location of source db")
	                 (argument 'dst help: "Location of destination db")))

     (def report
          (command 'report help: "report"
	                 (argument 'user help: "username")))

     (call-with-getopt process-args args
		                   program: "kunabi"
		                   help: "Cloudtrail parser in Gerbil"
		                   ct
		                   compact
		                   countdb
		                   db-copy
		                   index
		                   le
		                   lec
		                   ln
		                   ls
	                     q
		                   maintenance
		                   read
		                   repairdb
		                   report
		                   se
		                   sec
		                   sn
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
                 ((db-copy)
                  (db-copy .src .dst))
                 ((index)
                  (index))
                 ((le)
                  (le))
                 ((lec)
                  (lec))
                 ((ln)
                  (ln))
                 ((ls)
                  (ls))
                 ((maintenance)
                  (maintenance))
                 ((q)
                  (q .query))
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
                 ((sn)
                  (sn .event))
                 ((st)
                  (st)))))
