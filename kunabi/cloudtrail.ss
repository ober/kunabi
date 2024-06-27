;; -*- Gerbil -*-
;;; © jfournier
;;; aws cloudtrail parser

(import
  :clan/db/leveldb
  :clan/text/yaml
  :gerbil/gambit
  :ober/oberlib
  :std/actor-v18/io
  :std/crypto
  :std/debug/heap
  :std/debug/memleak
  :std/format
  :std/generic/dispatch
  :std/io
  :std/iter
  :std/misc/list
  :std/misc/threads
  :std/pregexp
  :std/srfi/1
  :std/srfi/95
  :std/sugar
  :std/text/hex
  :std/text/json
  :std/text/utf8
  :std/text/zlib
  )

(def version "0.08")

(export #t)

(def db-type leveldb:)
(def nil '#(nil))
(def program-name "kunabi")
(def config-file "~/.kunabi.yaml")

(def use-write-backs #t)

(def hc-hash (make-hash-table))

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
      (let ((key (utf8->string (leveldb-iterator-key itor)))
            (val (unmarshal-value (leveldb-iterator-value itor))))
        (if (hash-table? val)
          (displayln (format "k: ~a v: ~a" key (hash->list val)))
          (displayln (format "k: ~a v: ~a" key val))))
      (when (leveldb-iterator-valid? itor)
        (lp)))))

;; readers

(def (resolve-by-key key)
  (let ((itor (leveldb-iterator db)))
    (leveldb-iterator-seek itor (format "~a" key))
    (let lp ((res '()))
      (if (leveldb-iterator-valid? itor)
        (if (pregexp-match key (utf8->string (leveldb-iterator-key itor)))
	        (begin
	          (set! res (cons (unmarshal-value (leveldb-iterator-value itor)) res))
	          (leveldb-iterator-next itor)
	          (lp res))
	        res)
        res))))

(def (uniq-by-mid-prefix key)
  (dp (format ">-- uniq-by-mid-prefix: ~a" key))
  (let ((itor (leveldb-iterator db)))
    (leveldb-iterator-seek itor (format "~a#" key))
    (let lp ((res '()))
      (if (leveldb-iterator-valid? itor)
        (let ((k (utf8->string (leveldb-iterator-key itor))))
          (dp (format "k is ~a" k))
          (if (pregexp-match key k)
            (let ((mid (nth 1 (pregexp-split "#" k))))
	            (unless (member mid res)
                (set! res (cons mid res)))
	            (leveldb-iterator-next itor)
	            (lp res))
	          res))
        res))))

(def (sort-uniq-reverse lst)
  (reverse (unique! (sort! lst eq?))))

(def (index)
  (index-user)
  (index-errorCode)
  (index-event))

;; users
(def (ln)
  (for-each displayln (list-users)))

(def (list-users)
  (let (index "user!index")
    (if (db-key? index)
      (db-get index)
      (begin
        (index-user)
        (db-get index)))))

(def (index-user)
  (let ((index "user!index"))
    (db-rm index)
    (let ((entries
	         (sort-uniq-reverse
	          (uniq-by-mid-prefix "u#"))))
      (db-put index entries))))

;; events
(def (le)
  (for-each displayln (list-events)))

(def (list-events)
  (let (index "event!index")
    (if (db-key? index)
      (db-get index)
      (begin
        (index-event)
        (db-get index)))))

(def (index-event)
  (let ((index "event!index"))
    (db-rm index)
    (let ((entries
	         (sort-uniq-reverse
	          (uniq-by-mid-prefix "en#"))))
      (db-put index entries))))

;; error codes
(def (lec)
  (for-each displayln (list-errorCodes)))

(def (list-errorCodes)
  (let (index "event!errorCode")
    (if (db-key? index)
      (db-get index)
      (begin
        (index-errorCode)
        (db-get index)))))

(def (index-errorCode)
  (let ((index "event!errorCode"))
    (db-rm index)
    (let ((entries
	         (sort-uniq-reverse
	          (uniq-by-mid-prefix "ec#"))))
      (db-put index entries))))

;; other stuff
(def (match-key key)
  (resolve-records (resolve-by-key key)))

(def (report user)
  (displayln "** Total by Source IP")
  (tally-by-ip
   (resolve-by-key
    (format "u#~a#" user)))
  (displayln "** Total by Event Name")
  (tally-by-en
   (resolve-by-key
    (format "u#~a#" user))))

(def (reports)
  (for (user (list-users))
    (displayln (format "*** ~A" user))
    (report user)))

(def (sn key)
  (match-key (format "u#~a#" key)))

(def (se key)
  (match-key (format "en#~a#" key)))

(def (sec key)
  (match-key (format "ec#~a#" key)))

(def (st)
  (displayln "Totals: " " records: " (countdb)))

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
  (let (2G (expt 2 31))
    (when (< (##get-min-heap) 2G)
      (##set-min-heap! 2G)))

  (dp (format ">-- load-ct: ~a" dir))
  ;;(spawn watch-heap!)
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
  (parameterize ((read-json-key-as-symbol? #t))
    (hash-ref
     (read-json
      (open-input-string
       (utf8->string
        (uncompress file))))
     'Records)))

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
         " threads: " (length (all-threads))
	       " file: " file
	       )))))

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
    (let ((old wb))
      (spawn
       (lambda ()
	       (leveldb-write db old)))
      (set! wb (leveldb-writebatch))
      (set! write-back-count 0))))

(def (get-last-key)
  "Get the last key for use in compaction"
  (let ((itor (leveldb-iterator db)))
    (leveldb-iterator-seek-last itor)
    (let lp ()
      (leveldb-iterator-prev itor)
      (if (leveldb-iterator-valid? itor)
        (utf8->string (leveldb-iterator-key itor))
        (lp)))))

(def (get-first-key)
  "Get the last key for use in compaction"
  (let ((itor (leveldb-iterator db)))
    (leveldb-iterator-seek-first itor)
    (let lp ()
      (leveldb-iterator-next itor)
      (if (leveldb-iterator-valid? itor)
        (utf8->string (leveldb-iterator-key itor))
        (lp)))))

(def (print-rp rp)
  (let ((results []))
    (when rp
      (when (hash-table? rp)
        (dp (hash->string rp))
        (let-hash rp
          (when .?instancesSet
	          (when (hash-table? .instancesSet)
	            (let-hash .instancesSet
		            (when .?items
		              (when (list? .items)
		                (for-each
		                  (lambda (x)
			                  (when (hash-table? x)
			                    (hash-for-each
			                     (lambda (k v)
			                       (set! results (cons v results)))
			                     x)))
		                  .items))))))
          (when .?tableArn
            (set! results (cons .tableArn results)))
          (when .?repositoryNames
            (set! results (cons .repositoryNames results)))
          (when .?policyArn
            (set! results (cons .policyArn results)))
          (when .?GroupName
            (set! results (cons .GroupName results)))
          (when .?lookupAttributes
            (when (list? .lookupAttributes)
              (set! results (cons (hash->string (car .lookupAttributes)) results))))
          (when .?filter
            (when (hash-table? .filter)
              (set! results (cons (hash->string .filter) results))))
          (when .?tagFilters
            (when (hash-table? .tagFilters)
              (set! results (cons (hash->string .tagFilters) results))))
          (when .?filters
            (when (hash-table? .filters)
              (set! results (cons (hash->string .filters) results))))
          (when .?lookupAttributes
            (when (hash-table? .lookupAttributes)
              (set! results (cons (hash->string .lookupAttributes) results))))
          (when .?roleName
            (set! results (cons .roleName results)))
          (when .?bucketName
            (set! results (cons .bucketName results)))
          (when .?functionName
            (set! results (cons .functionName results)))
          (when .?tableName
            (set! results (cons .tableName results)))
          (when .?resourceArn
            (set! results (cons .resourceArn results)))
          (when .?instanceId
            (set! results (cons .instanceId results)))
          (when .?roleSessionName
            (set! results (cons .roleSessionName results)))
          (when .?secretId
            (set! results (cons .secretId results)))
          (when .?encryptionContext
            (set! results (cons (hash->string .encryptionContext) results)))
            ;; (let-hash .encryptionContext
            ;;   (when .?SecretArn
            ;;     (set! results (cons .SecretArn results)))))
          (when .?filterSet
            (set! results (cons (hash->string .filterSet) results)))
            ;; (when (hash-table? .filterSet)
            ;;   (let-hash .filterSet
            ;;     (when .?items
            ;;       (for (item .items)
            ;;         (when (hash-table? item)
            ;;           (let-hash item
            ;;             (when .?valueSet
            ;;               (when (hash-table? .valueSet)
            ;;                 (let-hash .valueSet
            ;;                   (when .items
            ;;                     (for (item .items)
            ;;                       (when (hash-table? item)
            ;;                         (let-hash item
            ;;                           (set! results (cons (format "~a: ~a" ...name .value) results))))))))))))))))

          (when .?Host
            (set! results (cons .Host results)))

          (when .?dBInstanceIdentifer
            (set! results (cons .dBInstanceIdentifer results)))

          (when .?DescribeInstanceCreditSpecificationsRequest
            (set! results (cons (hash->string .DescribeInstanceCreditSpecificationsRequest) results)))

          (when .?repositoryName
            (when (list? .repositoryName)
              (set! results (cons .repositoryName results))))

          (when .?targetGroupArn
            (set! results (cons .targetGroupArn results)))

          (when .?logGroupName
            (set! results (cons .logGroupName results)))

          (when .?resourceName
            (set! results (cons .resourceName results)))

          (when .?resource
            (set! results (cons .resource results)))

          (when .?expression
            (set! results (cons .expression results)))

          (when .?stackName
            (set! results (cons .stackName results)))

          (when .?keyId
            (set! results (cons .keyId results)))

          (when .?startRecordName
            (set! results (cons .startRecordName results)))

          (when .?id
            (set! results (cons .id results)))

          (when .?hostedZoneId
            (set! results (cons .hostedZoneId results)))

          (when (= (length results) 0)
            (dp (format "unhandled rp type: ~a" (hash->string rp)))
            (set! results (cons (hash->string rp) results))
            ))))
    ;;(displayln (format "results: ~a" results))
    (mixed-string-join (flatten results) "")))

(def (resolve-records ids)
  (when (list? ids)
    (let ((outs [[ "Date" "Name" "User" "Source" "Hostname" "Type" "Request" "User Agent" "Error Code" "Error Message"]]))
      (for (id ids)
        (let ((id2 (db-get id)))
	        (when (hash-table? id2)
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

(def (tally-by-en ids)
  (when (list? ids)
    (let ((outs [[ "Event Name" "Total" ]])
          (tally (make-hash-table)))
      (for (id ids)
        (let ((id2 (db-get id)))
	        (when (hash-table? id2)
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
	        (when (hash-table? id2)
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
  ;;(dp (format "+find-user ~a" (hash->list ui)))
  (let ((username ""))
    (when (hash-table? ui)
      (let-hash ui
	      (let ((type (hash-get ui 'type)))
          (dp (format "find-user: type is ~a" type))
          (if type
	          (cond
	           ((string=? "SAMLUser" type)
	            (set! username .userName))
	           ((string=? "IAMUser" type)
	            (set! username .userName))
	           ((string=? "AWSAccount" type)
	            (set! username (format "~a:~a" .?principalId .?accountId)))
	           ((string=? "AssumedRole" type)
	            (if (hash-key? ui 'sessionContext)
		            (when (hash-table? .?sessionContext)
		              (let-hash .?sessionContext
                    (when (hash-table? .?sessionIssuer)
		                  (let-hash .?sessionIssuer
			                  (set! username (format "~a/~a" .userName (cadr (pregexp-split ":" ...principalId))))))))
		            (begin
		              (displayln (format "Fall thru find-user ~a~%" (hash->list ui)))
		              (set! username (cadr (pregexp-split ":" .principalId)))))) ;; not found go with this for now.
	           ((string=? "AWSService" type)
	            (set! username (hash-get ui 'invokedBy)))
	           ((string=? "Root" type)
	            (set! username (format "~a invokedBy: ~a" (hash-get ui 'userName) (hash-get ui 'invokedBy))))
	           ((string=? "FederatedUser" type)
	            (when (hash-table? .?sessionContext)
		            (let-hash .?sessionContext
		              (when (hash-table? .?sessionIssuer)
		                (set! username (hash-ref .?sessionIssuer 'userName))))))
             ) ;; cond
             (else
              (begin
                (set! username (format "~a-~a" .?invokedBy .?accountId))))
	           (displayln "error: type :" type " not found in ui" (hash->str ui))))))
    username))

(def (process-row row)
  (dp (format "process-row: row: ~a" (hash->list row)))
  (let-hash row
    (dp (hash->string row))
    (let*
	      ((user (find-user .?userIdentity))
         (req-id (or .?requestID .?eventID))
	       (epoch (date->epoch2 .?eventTime))
	       (h (hash
	           ;;(ar .?awsRegion)
	           (ec .?errorCode)
	           (em .?errorMessage)
	           (eid .?eventID)
	           (en  .?eventName)
	           (es .?eventSource)
	           (time .?eventTime)
	           (et .?eventType)
	           (rid .?recipientAccountId)
	           (rp (print-rp .?requestParameters))
	           (user user)
	           (re .?responseElements)
	           (sia .?sourceIPAddress)
	           (ua .?userAgent)
	           ;;(ui (hash-it .?userIdentity))
	           )))

      (unless (getenv "kunabiro" #f)
        (set! write-back-count (+ write-back-count 1))
        (db-batch req-id h)
        (when (string=? user "")
          (displayln "Error: missing user: " user))
        (when (string? user)
	        (db-batch (format "u#~a#~a" user epoch) req-id))
        (when (string? .?eventName)
	        (db-batch (format "en#~a#~a" .?eventName epoch) req-id))
        (when (string? .?errorCode)
	        (db-batch (format "ec#~a#~a" .errorCode epoch) req-id))
        ))))

;; db stuff

(def (db-batch key value)
  (unless (string? key) (dp (format "key: ~a val: ~a" (##type-id key) (##type-id value))))
  (leveldb-writebatch-put wb key (marshal-value value)))

(def (db-put key value)
  (dp (format "<----> db-put: key: ~a val: ~a" key value))
  (leveldb-put db key (marshal-value value)))

(def (db-rm key)
  (dp (format "<----> db-rm: key: ~a" key))
  (leveldb-delete db key))

(def (ensure-db)
  (unless db
    (set! db (db-open))))

(def (db-open)
  (dp ">-- db-open")
  (let ((db-dir (or (getenv "kunabidb" #f) (format "~a/kunabi-db/" (user-info-home (user-info (user-name)))))))
    (dp (format "db-dir is ~a" db-dir))
    (unless (file-exists? db-dir)
      (create-directory* db-dir))
    (let ((location (format "~a/records" db-dir)))
      (leveldb-open location (leveldb-options
			                        paranoid-checks: #f
			                        max-open-files: (def-num (getenv "k_max_files" 500000))
			                        bloom-filter-bits: (def-num (getenv "k_bloom_bits" #f))
			                        compression: #t
			                        block-size: (def-num (getenv "k_block_size" #f))
			                        write-buffer-size: (def-num (getenv "k_write_buffer" (* 102400 1024 16)))
			                        lru-cache-capacity: (def-num (getenv "k_lru_cache" 10000)))))))

(def (db-copy src dst)
  "Copy all item from src to dst"
  (let* ((src-db (leveldb-open (format "~a/records" src)))
	       (itor (leveldb-iterator src-db))
	       (dst-db (leveldb-open (format "~a/records" dst))))
    (leveldb-iterator-seek-first itor)
    (let lp ()
      (let ((key (utf8->string (leveldb-iterator-key itor)))
            (val (leveldb-iterator-value itor)))
	      (if (leveldb-key? dst-db (format "~a" key))
	        (dp (format "~a key already exists in dst" key))
	        (leveldb-put dst-db key val))
	      (leveldb-delete src-db key))
      (leveldb-iterator-next itor)
      (if (leveldb-iterator-valid? itor)
	      (lp)
	      (begin
	        (leveldb-close src-db)
	        (leveldb-close dst-db))))))

(def (db-get key)
  (dp (format "db-get: ~a" key))
  (let ((ret (leveldb-get db (format "~a" key))))
    (if (u8vector? ret)
      (unmarshal-value ret)
      "N/A")))

(def (db-key? key)
  (dp (format ">-- db-key? with ~a" key))
  (leveldb-key? db (format "~a" key)))

(def (db-write)
  (dp "in db-write")
  (leveldb-write db wb))

(def (db-close)
  (dp "in db-close")
  (leveldb-close db))

(def (db-init)
  (dp "in db-init")
  (leveldb-writebatch))

;; leveldb stuff
(def (get-leveldb key)
  (displayln "get-leveldb: " key)
  (try
   (let* ((bytes (leveldb-get db (format "~a" key)))
          (val (if (u8vector? bytes)
                 (unmarshal-value bytes)
                 nil)))
     val)
   (catch (e)
     (raise e))))

(def (remove-leveldb key)
  (dp (format "remove-leveldb: ~a" key)))

(def (compact)
  "Compact some stuff"
  (let* ((itor (leveldb-iterator db))
         (first (get-first-key))
         (last (get-last-key)))
    (displayln "First: " first " Last: " last)
    (leveldb-compact-range db first last)))

(def (count-key key)
  "Get a count of how many records are in db"
  (let ((itor (leveldb-iterator db)))
    (leveldb-iterator-seek-first itor)
    (let lp ((count 0))
      (leveldb-iterator-next itor)
      (if (leveldb-iterator-valid? itor)
        (begin
          (if (pregexp-match key (utf8->string (leveldb-iterator-key itor)))
	          (begin
	            (displayln (format "Found one ~a" (utf8->string (leveldb-iterator-key itor))))
	            (lp (1+ count)))
	          (lp count)))
        count))))

(def (countdb)
  "Get a count of how many records are in db"
  (let ((mod 1000000)
	      (itor (leveldb-iterator db)))
    (leveldb-iterator-seek-first itor)
    (let lp ((count 1))
      (when (= (modulo count mod) 0)
	      (displayln count))
      (leveldb-iterator-next itor)
      (if (leveldb-iterator-valid? itor)
        (lp (1+ count))
        count))))

(def (repairdb)
  "Repair the db"
  (let ((db-dir (or (getenv "kunabidb" #f) (format "~a/kunabi-db/" (user-info-home (user-info (user-name)))))))
    (leveldb-repair-db (format "~a/records" db-dir))))

(def (def-num num)
  (if (string? num)
    (string->number num)
    num))

(def (maintenance)
  (let lp ()
    (thread-sleep! 2147483647)
    (lp)))
