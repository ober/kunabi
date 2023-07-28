;; -*- Gerbil -*-
;;; © jfournier
;;; aws cloudtrail parser

(import
  :gerbil/gambit
  :gerbil/gambit/os
  :gerbil/gambit/threads
  :std/actor
  :std/db/dbi
  :std/db/postgresql
  :std/db/postgresql-driver
  :std/db/leveldb
  :std/debug/heap
  :std/debug/memleak
  :std/format
  :std/generic/dispatch
  :std/iter
  :std/logger
  :std/misc/list
  :std/misc/threads
  :std/misc/queue
  :std/net/address
  :std/net/httpd
  :std/pregexp
  :std/srfi/1
  :std/srfi/95
  :std/sugar
  :std/text/json
  :std/text/yaml
  :std/text/zlib
  :ober/oberlib)

(declare (not optimize-dead-definitions))

(def version "0.07")

(export #t)

(def db-type leveldb:)
(def nil '#(nil))
(def program-name "kunabi")
(def config-file "~/.kunabi.yaml")

(def use-write-backs #t)

(def hc-hash (make-hash-table))
(def vpc-totals (make-hash-table))

(def wb (db-init))
(def db (db-open))

(def HC 0)
(def write-back-count 0)
(def max-wb-size (def-num (getenv "k_max_wb" 100000)))
(def tmax (def-num (getenv "tmax" 12)))
(def indices-hash (make-hash-table))

(def (load-config)
  (let ((config (hash)))
    (hash-for-each
     (lambda (k v)
       (hash-put! config (string->symbol k) v))
     (car (yaml-load config-file)))
    config))

(def (ls)
  (list-records))

(def (list-records)
  "Print all records"
  (let (itor (leveldb-iterator db))
    (leveldb-iterator-seek-first itor)
    (let lp ()
      (leveldb-iterator-next itor)
      (let ((key (bytes->string (leveldb-iterator-key itor)))
            (val (u8vector->object (leveldb-iterator-value itor))))
        (if (table? val)
          (displayln (format "k: ~a v: ~a" key (hash->list val)))
          (displayln (format "k: ~a v: ~a" key val))))
      (when (leveldb-iterator-valid? itor)
        (lp)))))

(def (lvf file)
  (read-vpc-file file))

(def (se event)
  (search-event event))

(def (sr event)
  (search-event event))

(def (sip event)
  (search-event event))

(def (sn event)
  (search-event event))

(def (sec event)
  (search-event event))

(def (lec)
  (list-index-entries "I-errors"))

(def (st)
  (displayln "Totals: "
             " records: " (countdb)
             ))

(def (read file)
  (read-ct-file file))

(def (ln)
  "List User names"
  (list-index-entries "I-users"))

(def (le)
  "List Events"
  (list-index-entries "I-events"))

(def (lr)
  "List regions"
  (list-index-entries "I-aws-region"))

(def (source-ips)
  (list-source-ips))

;; (def (summaries)
;;   (summary-by-ip))

(def (vpc file)
  (load-vpc file))

(def (ct file)
  (load-ct file))

(def (find-ct-files dir)
  (find-files
   dir
	 (lambda (filename)
		 (and (equal? (path-extension filename) ".gz")
			    (not (equal? (path-strip-directory filename) ".gz"))))))

(def (load-ct dir)
  "Entry point for processing cloudtrail files"
  (dp (format ">-- load-ct: ~a" dir))
  (spawn watch-heap!)
  (let* ((count 0)
	       (ct-files (find-ct-files "."))
         (pool []))
    (for (file ct-files)
      (cond-expand
        (gerbil-smp
         (while (< tmax (length (all-threads)))
           (displayln "sleeping")
           (thread-sleep! .05))
         (let ((thread (spawn (lambda () (read-ct-file file)))))
           (set! pool (cons thread pool))))
        (else
         (read-ct-file file)))
      (flush-all?)
      (set! count 0))
    (cond-expand (gerbil-smp (for-each thread-join! pool)))
    (db-write)
    (db-close)))

(def (file-already-processed? file)
  (dp "in file-already-processed?")
  (let* ((short (get-short file))
         (seen (db-key? (format "F-~a" short))))
    seen))

(def (mark-file-processed file)
  (dp "in mark-file-processed")
  (let ((short (get-short file)))
    (format "marking ~A~%" file)
    (db-batch (format "F-~a" short) "t")))

(def (load-ct-file file)
  (hash-ref
	 (read-json
		(open-input-string
		 (bytes->string
			(uncompress file))))
	 'Records))

(def (read-ct-file file)
  (ensure-db)
  (dp (format "read-ct-file: ~a" file))
  (unless (file-already-processed? file)
    (let ((btime (time->seconds (current-time)))
	        (count 0))
      (dp (memory-usage))
      (call-with-input-file file
	      (lambda (file-input)
	        (let ((mytables (load-ct-file file-input)))
            (for-each
              (lambda (row)
                (set! count (+ count 1))
                (process-row row))
              mytables))
          (mark-file-processed file)))

      (let ((delta (- (time->seconds (current-time)) btime)))
        (displayln
         "rps: " (float->int (/ count delta ))
         " size: " count
         " delta: " delta
         " threads: " (length (all-threads)))))))

(def (number-only obj)
  (if (number? obj)
    obj
    (string->number obj)))

(def (get-short str)
  (cond
   ((string-rindex str #\_)
    =>
    (lambda (ix)
      (cond
       ((string-index str #\. ix)
	      =>
        (lambda (jx)
	        (substring str (1+ ix) jx)))
       (else #f))))
   (else str)))

(def (getf field row)
  (hash-get row field))

(def (flush-all?)
  (dp (format "write-back-count && max-wb-size ~a ~a" write-back-count max-wb-size))
  (if (> write-back-count max-wb-size)
    (begin
      (displayln "writing.... " write-back-count)
      (leveldb-write db wb)
      (set! write-back-count 0))))

(def (get-last-key)
  "Get the last key for use in compaction"
  (let ((itor (leveldb-iterator db)))
    (leveldb-iterator-seek-last itor)
    (let lp ()
      (leveldb-iterator-prev itor)
      (if (leveldb-iterator-valid? itor)
        (bytes->string (leveldb-iterator-key itor))
        (lp)))))

(def (get-first-key)
  "Get the last key for use in compaction"
  (let ((itor (leveldb-iterator db)))
    (leveldb-iterator-seek-first itor)
    (let lp ()
      (leveldb-iterator-next itor)
      (if (leveldb-iterator-valid? itor)
        (bytes->string (leveldb-iterator-key itor))
        (lp)))))

(def (get-next-id max)
  (let ((maxid (1+ max)))
    (if (db-key? (format "~a" maxid))
      (get-next-id (* 2 maxid))
      maxid)))

(def (inc-hc)
  "increment HC to next free id."
  (let ((next (get-next-id HC)))
    (set! HC next)
    (db-batch "HC" (format "~a" HC))))

(def (indices-report)
  (let ((total 0))
    (hash-for-each
     (lambda (k v)
       (let ((count (hash-length v)))
	       (displayln k ":" count " v: " v " first:" (hash-keys v))
	       (set! total (+ total count))))
     indices-hash)
    (displayln "indicies count total: " total)))

(def (flush-vpc-totals)
  (for (cid (hash-keys vpc-totals))
    (db-batch (format "~a" cid) (hash-get vpc-totals cid))))

(def (count-index idx)
  (if (db-key? idx)
    (let* ((entries (hash-keys (db-get idx)))
           (count (length entries)))
      count)))

(def (list-index-entries idx)
  (if (db-key? idx)
    (let ((entries (hash-keys (db-get idx))))
      (if (list? entries)
	      (for-each displayln (sort! entries eq?))
	      (begin
	        (displayln "did not get list back from entries")
	        (type-of entries))))
    (displayln "no idx found for " idx)))

(def (resolve-records ids)
  (when (list? ids)
    (let ((outs [[ "Date" "Name" "User" "Source" "Hostname" "Type" "Request" "User Agent" "Error Code" "Error Message" ]]))
      (for (id ids)
        (let ((id2 (db-get id)))
          (when (table? id2)
            (let-hash id2
              (set! outs (cons [
                                .?time
		                            .?en
		                            .?user
		                            .?es
		                            .?sia
		                            .?et
		                            .?rp
		                            .?ua
		                            .?ec
		                            .?em
                                ] outs))))))
      (style-output outs "org-mode"))))

(def (get-host-name ip)
  (if (pregexp-match "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}" ip)
    (let ((lookup (host-info ip)))
      (if (host-info? lookup)
	      (let ((lookup-name (host-info-name lookup)))
	        lookup-name)))
    ip))

;;;;;;;;;; vpc stuff
(def (process-vpc-row row)
  (with ([ date
	         version
	         account_id
	         interface-id
	         srcaddr
	         dstaddr
	         srcport
	         dstport
	         protocol
	         packets
	         bytez
	         start
	         end
	         action
	         status
	         ] (string-split row #\space))
    (let* ((convo (format "C-~a-~a-~a-~a-~a" srcaddr srcport dstaddr dstport protocol))
	         (cid (memo-cid convo)))
      (add-bytez cid bytez))))

(def (add-bytez cid bytez)
  (if (hash-key? vpc-totals cid)
    (let ((total (hash-get vpc-totals cid))) ;; we have this key, let's update total
      (hash-put! vpc-totals cid (+ (any->int total) (any->int bytez))))
    (hash-put! vpc-totals cid bytez))) ;; new entry to be created and total

(def (read-vpc-file file)
  (let ((count 0)
	      (bundle 100000)
	      (btime 0)
	      (etime 0))
    (unless (file-already-processed? file)
      (call-with-input-file file
        (lambda (file-input)
          (let ((data (time (bytes->string (uncompress file-input)))))
            (for (row (string-split data #\newline))
              (set! count (1+ count))
              (if (= (modulo count bundle) 0)
                (begin
                  (set! etime (time->seconds (current-time)))
                  (display #\return)
                  (displayln (format "rps: ~a count:~a" (float->int (/ bundle (- etime btime))) count))
                  (set! btime (time->seconds (current-time)))))
              (process-vpc-row row))))))
    count))

(def (load-vpc dir)
  (let ((rows 0)
	      (btime 0)
	      (total-count 0)
	      (etime 0)
        (files (find-files
                dir
                (lambda
                    (filename)
                  (and
                    (equal? (path-extension filename) ".gz")
                    (not (equal? (path-strip-directory filename) ".gz")))))))

    (for (file files)
      (displayln ".+")
      (let* ((btime (time->seconds (current-time)))
             (rows (read-vpc-file file))
             (etime (time->seconds (current-time))))
        (displayln "rows: " rows)
        (set! total-count (+ total-count rows))
        (set! files (+ files 1))
        (mark-file-processed file)
        (flush-vpc-totals)))
    (flush-vpc-totals)
    (db-write)
    (db-close)
    (displayln "Total: " total-count)))

;; (def (summary-by-ip)
;;   (let (summaries (sort! (hash-keys (db-get "I-source-ip-address")) eq?))
;;     (for (sumation summaries)
;;       (summary sumation)
;;       (displayln ""))))

(def (ip? x)
  (pregexp-match "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}" x))

(def (add-host-ent ip)
  (displayln ip)
  (if (ip? ip)
    (let* ((idx (format "H-~a" ip))
           (lookup (host-info ip))
           (resolved? (db-key? idx)))
      (unless resolved?
        (when (host-info? lookup)
          (let ((lookup-name (host-info-name lookup)))
            (unless (string=? lookup-name ip)
              (db-batch (format "H-~a" ip) lookup-name))))))))

(def (resolve-all-hosts)
  (let ((threads [])
        (entries (hash-keys (db-get "I-source-ip-address"))))
    (for (entry entries)
      (add-host-ent entry))))

(def (list-source-ips)
  (let (entries (sort! (hash-keys (db-get "I-source-ip-address")) eq?))
    (for (entry entries)
      (let ((hname (format "H-~a" entry)))
        (if (db-key? hname)
          (displayln (format "~a: ~a" entry (db-get hname))))))))

(def (find-user ui)
  (let ((username ""))
    (when (table? ui)
      (let-hash ui
        (let ((type (hash-get ui 'type)))
          (if type
            (cond
             ((string=? "SAMLUser" type)
              (set! username .userName))
             ((string=? "IAMUser" type)
              (set! username .userName))
             ((string=? "AWSAccount" type)
              (set! username (format "~a" .?principalId)))
             ((string=? "AssumedRole" type)
              (if (hash-key? ui 'sessionContext)
                (when (table? .?sessionContext)
                  (let-hash
                      .?sessionContext
                    (when (table? .?sessionIssuer)
                      (let-hash
                          .?sessionIssuer
                        (set! username .userName)))))
                (begin
                  (displayln (format "Fall thru find-user ~a~%" (hash->list ui)))
                  (set! username .principalId)))) ;; not found go with this for now.
             ((string=? "AWSService" type)
              (set! username (hash-get ui 'invokedBy)))
             ((string=? "Root" type)
              (set! username (format "~a invokedBy: ~a" (hash-get ui 'userName) (hash-get ui 'invokedBy))))
             ((string=? "FederatedUser" type)
              (when (table? .?sessionContext)
                (let-hash .?sessionContext
                  (when (table? .?sessionIssuer)
                    (set! username (hash-ref .?sessionIssuer 'userName))))))
             (else
              (set! username (format "Unknown Type: ~a" (hash->str ui)))))
            (displayln "error: type :" type " not found in ui" (hash->str ui))))))
    username))

(def vpc-fields '(
                  bytez
                  date
                  dstaddr
                  dstport
                  endf
                  interface-id
                  packets
                  protocol
                  srcaddr
                  srcport
                  start
                  status
                  action
                  ))

(def (inc-hash hashy key)
  (dp (format "~a:~a" (hash->list hashy) key))
  (if (hash-key? hashy key)
    (hash-put! hashy key (+ 1 (hash-get hashy key)))
    (hash-put! hashy key 1)))

;; (def (summary key)
;;   (let ((sum (hash))
;;         (entries (hash-keys (db-get (format "I-~a" key)))))
;;     (for (entry entries)
;;       (if (db-key? (format "~a" entry))
;;         (let ((row (db-get (format "~a" entry))))
;;           (if (table? row)
;;             (let-hash row
;;               (dp (format "~a" (hash->list row)))
;;               (inc-hash sum (get-val .event-name))
;;               (inc-hash sum (get-val .event-type))
;;               (inc-hash sum (get-val .user))
;;               (inc-hash sum (get-val .source-ip-address))
;;               (inc-hash sum (get-val .error-message))
;;               (inc-hash sum (get-val .error-code))
;;               (inc-hash sum (get-val .aws-region))
;;               )))
;;         (displayln "No index for " entry)))

    ;; (display  (format " ~a: " key))
    ;; (if (ip? key) (display (db-get (format "H-~a" key))))
    ;; (hash-for-each
    ;;  (lambda (k v)
    ;;    (display (format " ~a:~a " k v)))
    ;;  sum)))

(def (process-row row)
  (dp (format "process-row: row: ~a" (hash->list row)))
  (let-hash row
    (let*
        ((user (find-user .?userIdentity))
         (req-id (or .?requestID .?eventID))
         (epoch (date->epoch2 .?eventTime))
         (h (hash
             (ar .?awsRegion)
             (ec .?errorCode)
             (em .?errorMessage)
             (eid .?eventID)
             (en  .?eventName)
             (es .?eventSource)
             (time .?eventTime)
             (et .?eventType)
             (rid .?recipientAccountId)
             (rp .?requestParameters)
             (user user)
             (re .?responseElements)
             (sia .?sourceIPAddress)
             (ua .?userAgent)
             (ui .?userIdentity))))

      (set! write-back-count (+ write-back-count 1))
      (db-batch req-id h)
      (when (string? user)
        (db-batch (format "user:~a:~a" user epoch) req-id))
      (when (string? .?eventName)
        (db-batch (format "event-name:~a:~a" .?eventName epoch) req-id))
      (when (string? .?errorCode)
        (db-batch (format "errorCode:~a:~a" .errorCode epoch) req-id))
      )))
