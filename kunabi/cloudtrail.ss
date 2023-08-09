;; -*- Gerbil -*-
;;; © jfournier
;;; aws cloudtrail parser

(import
  :gerbil/gambit
  :gerbil/gambit/os
  :gerbil/gambit/threads
  :std/text/utf8
  :std/db/lmdb
  :std/debug/heap
  :std/debug/memleak
  :std/format
  :std/generic/dispatch
  :std/iter
  :std/misc/list
  :std/misc/threads
  :std/pregexp
  :std/srfi/1
  :std/srfi/95
  :std/sugar
  :std/text/json
  :std/text/yaml
  :std/text/zlib
  :ober/oberlib)

(declare (not optimize-dead-definitions))

(def version "0.08")

(export #t)

(def nil '#(nil))
(def program-name "kunabi")
(def config-file "~/.kunabi.yaml")

(def use-write-backs #t)

(def hc-hash (make-hash-table))

(def env (db-init))
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

;; (def (ls)
;;   (list-records))

;; (def (list-records)
;;   "Print all records"
;;   (let (itor (leveldb-iterator db))
;;     (leveldb-iterator-seek-first itor)
;;     (let lp ()
;;       (leveldb-iterator-next itor)
;;       (let ((key (utf8->string (leveldb-iterator-key itor)))
;;             (val (u8vector->object (leveldb-iterator-value itor))))
;;         (if (table? val)
;;           (displayln (format "k: ~a v: ~a" key (hash->list val)))
;;           (displayln (format "k: ~a v: ~a" key val))))
;;       (when (leveldb-iterator-valid? itor)
;;         (lp)))))

;; readers

;; (def (resolve-by-key key)
;;   (let ((itor (leveldb-iterator db)))
;;     (leveldb-iterator-seek itor (format "~a" key))
;;     (let lp ((res '()))
;;       (if (leveldb-iterator-valid? itor)
;;         (if (pregexp-match key (utf8->string (leveldb-iterator-key itor)))
;;           (begin
;;             (set! res (cons (u8vector->object (leveldb-iterator-value itor)) res))
;;             (leveldb-iterator-next itor)
;;             (lp res))
;;           res)
;;         res))))

;; (def (uniq-by-mid-prefix key)
;;   (let ((itor (leveldb-iterator db)))
;;     (leveldb-iterator-seek itor (format "~a#" key))
;;     (let lp ((res '()))
;;       (if (leveldb-iterator-valid? itor)
;;         (let ((k (utf8->string (leveldb-iterator-key itor))))
;;           (if (pregexp-match key k)
;;             (let ((mid (nth 1 (pregexp-split "#" k))))
;;               (unless (member mid res)
;;                 (set! res (cons mid res)))
;;               (leveldb-iterator-next itor)
;;               (lp res))
;;             res))
;;         res))))

(def (sort-uniq-reverse lst)
   (reverse (unique! (sort! lst eq?))))

;; (def (index)
;;   (index-user)
;;   (index-errorCode)
;;   (index-event))

;; ;; users
;; (def (ln)
;;   (for-each displayln (list-users)))

;; (def (index-user)
;;   (db-put "user!index" (list-users)))

;; (def (list-users)
;;   (let (index "user!index")
;;     (if (db-key? index)
;;       (db-get index)
;;       (let (entries
;;             (sort-uniq-reverse
;;              (uniq-by-mid-prefix "user")))
;;         (db-put index entries)
;;         entries))))

;; ;; events
;; (def (le)
;;   (for-each displayln (list-events)))

;; (def (index-event)
;;   (db-put "event!index" (list-events)))

;; (def (list-events)
;;   (let (index "event!index")
;;     (if (db-key? index)
;;       (db-get index)
;;       (let (entries
;;             (sort-uniq-reverse
;;              (uniq-by-mid-prefix "eventName")))
;;         (db-put index entries)
;;         entries))))

;; error codes
(def (lec)
  (for-each displayln (list-errorCodes)))

(def (index-errorCode)
  (db-put "event!errorCode" (list-errorCodes)))

(def (list-errorCodes)
  (let (index "event!errorCode")
    (if (db-key? index)
      (db-get index)
      (let (entries
            (sort-uniq-reverse
             (uniq-by-mid-prefix "errorCode")))
        (db-put index entries)
        entries))))

(def (match-key key)
  (resolve-records (resolve-by-key key)))

(def (report user)
  (displayln "** Total by Source IP")
  (tally-by-ip
   (resolve-by-key
    (format "user#~a#" user)))
  (displayln "** Total by Event Name")
  (tally-by-en
   (resolve-by-key
    (format "user#~a#" user))))

(def (reports)
  (for (user (list-users))
    (displayln (format "*** ~A" user))
    (report user)))

(def (sn key)
  (match-key (format "user#~a#" key)))

(def (se key)
  (match-key (format "eventName#~a#" key)))

(def (sec key)
  (match-key (format "errorCode#~a#" key)))

(def (st)
  (displayln "Totals: "
             " records: " (countdb)
             ))

(def (read file)
  (read-ct-file file))

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
           (thread-yield!))
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
		 (utf8->string
			(uncompress file))))
	 'Records))

(def (read-ct-file file)
  (ensure-db)
  (##gc)
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

(def (flush-all?)
  (dp (format "write-back-count && max-wb-size ~a ~a" write-back-count max-wb-size))
  (when (> write-back-count max-wb-size)
    (displayln "writing.... " write-back-count)
    ;;(leveldb-write db wb)
    ;;(compact)
    (set! write-back-count 0)))

;; (def (get-last-key)
;;   "Get the last key for use in compaction"
;;   (let ((itor (leveldb-iterator db)))
;;     (leveldb-iterator-seek-last itor)
;;     (let lp ()
;;       (leveldb-iterator-prev itor)
;;       (if (leveldb-iterator-valid? itor)
;;         (utf8->string (leveldb-iterator-key itor))
;;         (lp)))))

;; (def (get-first-key)
;;   "Get the last key for use in compaction"
;;   (let ((itor (leveldb-iterator db)))
;;     (leveldb-iterator-seek-first itor)
;;     (let lp ()
;;       (leveldb-iterator-next itor)
;;       (if (leveldb-iterator-valid? itor)
;;         (utf8->string (leveldb-iterator-key itor))
;;         (lp)))))

(def (resolve-records ids)
  (when (list? ids)
    (let ((outs [[ "Date" "Name" "User" "Source" "Hostname" "Type" "Request" "User Agent" "Error Code" "Error Message" "UserIdentify"]]))
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
		                            (if (table? .?rp) (hash->list .?rp) .?rp)
		                            .?ua
		                            .?ec
		                            .?em
                                .?ua
                                ] outs))))))
      (style-output outs "org-mode"))))

(def (tally-by-en ids)
  (when (list? ids)
    (let ((outs [[ "Event Name" "Total" ]])
          (tally (make-hash-table)))
      (for (id ids)
        (let ((id2 (db-get id)))
          (when (table? id2)
            (let-hash id2
              (let ((en .?en))
                (if (hash-ref tally en #f)
                  (hash-put! tally en (+ 1 (hash-ref tally en)))
                  (hash-put! tally en 1)))))))
      (for (k (sort! (hash-keys tally) string<?))
        (set! outs (cons [
                          k
                          (hash-ref tally k)
                          ] outs)))
      (style-output outs "org-mode"))))

(def (tally-by-ip ids)
  (when (list? ids)
    (let ((outs [[ "Host" "Totals" ]])
          (tally (make-hash-table)))
      (for (id ids)
        (let ((id2 (db-get id)))
          (when (table? id2)
            (let-hash id2
              (let ((sia .?sia))
                (if (hash-ref tally sia #f)
                  (hash-put! tally sia (+ 1 (hash-ref tally sia)))
                  (hash-put! tally sia 1)))))))
      (for (k (sort! (hash-keys tally) string<?))
        (set! outs (cons [
                          (get-host-name k)
                          (hash-ref tally k)
                          ] outs)))
      (style-output outs "org-mode"))))

(def (get-host-name ip)
  (if (pregexp-match "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}" ip)
    (let ((lookup (host-info ip)))
      (if (host-info? lookup)
	      (let ((lookup-name (host-info-name lookup)))
	        lookup-name)))
    ip))

;;;;;;;;;; vpc stuff

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
                  (let-hash .?sessionContext
                    (when (table? .?sessionIssuer)
                      (let-hash .?sessionIssuer
                        (set! username (format "~a/~a" .userName (cadr (pregexp-split ":" ...principalId))))))))
                (begin
                  (displayln (format "Fall thru find-user ~a~%" (hash->list ui)))
                  (set! username (cdr (pregexp-split ":" .principalId)))))) ;; not found go with this for now.
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
             ;;(re .?responseElements)
             (sia .?sourceIPAddress)
             (ua .?userAgent)
             (ui .?userIdentity))))

      (set! write-back-count (+ write-back-count 1))
      (db-batch req-id h)
      (when (string? user)
        (db-batch (format "user#~a#~a" user epoch) req-id))
      (when (string? .?eventName)
        (db-batch (format "eventName#~a#~a" .?eventName epoch) req-id))
      (when (string? .?errorCode)
        (db-batch (format "errorCode#~a#~a" .errorCode epoch) req-id))
      )))


;; lmdb stuff

(def (db-open)
  (dp (format "in db-open"))
  (lmdb-open-db env "kunabi-lmdb" lmdb-create: #t))

(def (ensure-db)
  (unless db
    (set! db (db-open))))

(def (db-key? key)
  (dp (format ">-- db-key? with ~a" key))
  (lmdb-get db (format "~a" key)))

(def (db-close)
  (dp "in db-close")
  (lmdb-close-db db)
  (lmdb-close env))

(def (db-init)
  (lmdb-open "~/kunabi-lmdb" mapsize: 1000000000))

(def (db-get key)
  (let (txn (lmdb-txn-begin env))
    (try
     (let* ((bytes (lmdb-get txn db key))
	          (val (if bytes
		               (call-with-input-u8vector (uncompress bytes) read-json)
		               nil)))
       (lmdb-txn-commit txn)
       val)
     (catch (e)
       (lmdb-txn-abort txn)
       (display e)
       (displayln "error kunabi-store-get: key:" key)
       ;;(raise e)
       ))))

(def (db-put key val)
  (let (txn (lmdb-txn-begin env))
    (try
     (lmdb-put txn db key (compress (call-with-output-bytes (lambda (port) (write-json val port))))))
     (lmdb-txn-commit txn)
     (catch (e)
       (lmdb-txn-abort txn)
       (display e)
       (displayln "error kunabi-store-put: key:" key " val:" val)
       ;;(raise e)
       )))


(def (def-num num)
  (if (string? num)
    (string->number num)
    num))
