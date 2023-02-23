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
(def version "0.06")

(export #t)

(def db-type leveldb:)
(def nil '#(nil))
(def program-name "kunabi")
(def config-file "~/.kunabi.yaml")

(def use-write-backs #t)

(setenv "GERBIL_HOME" (format "~a/.gerbil" (user-info-home (user-info (user-name)))))

(def hc-hash (make-hash-table))
(def vpc-totals (make-hash-table))

(def wb (db-init))
(def db (db-open))

(def HC 0)
(def write-back-count 0)
(def max-wb-size (def-num (getenv "k_max_wb" 100000)))
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
      (displayln (format "k: ~a"
                         (bytes->string (leveldb-iterator-key itor))))
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
             " users: " (count-index "I-users")
             " errors: " (count-index "I-errors")
             " regions: " (count-index "I-aws-region")
             " events: " (count-index "I-events")
             " files: " (count-by-key "F*")
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

(def (summaries)
  (summary-by-ip))

(def (vpc file)
  (load-vpc file))

(def (ct file)
  (load-ct file))

(def (load-ct dir)
  ;;(##gc-report-set! #t)
  (dp (format ">-- load-ct: ~a" dir))
  ;;(spawn watch-heap!)
  (load-indices-hash)
  (let* ((files 0)
	       (rows 0)
         (count 0)
         (mod 1)
	       (etime 0)
	       (btime (time->seconds (current-time)))
	       (total-count 0)
	       (ct-files
	        (find-files dir
		                  (lambda (filename)
			                  (and (equal? (path-extension filename) ".gz")
			                       (not (equal? (path-strip-directory filename) ".gz"))))))
	       (file-count (length ct-files)))

    (for (file ct-files)
      ;;(spawn (lambda ()
      (read-ct-file file)
      ;;))
      (set! count (+ 1 count))
      (flush-all?)
      (set! count 0))
    (flush-indices-hash)
    (db-write)
    (db-close)))

(def (file-already-processed? file)
  (dp "in file-already-processed?")
  (let* ((short (get-short file))
         (seen (db-key? (format "F-~a" short))))
    seen))

(def (add-to-index index entry)
  (dp (format "in add-to-index index: ~a entry: ~a" index entry))
  (let ((index-in-global-hash? (hash-key? indices-hash index)))
    (dp (format  "index-in-global-hash? ~a ~a" index-in-global-hash? index))
    (if index-in-global-hash?
      (new-index-entry index entry)
      (begin
	      (dp (format "ati: index not in global hash for ~a. adding" index))
	      (hash-put! indices-hash index (hash))
	      (let ((have-db-entry-for-index (db-key? (format "I-~a" index))))
	        (dp (format "have-db-entry-for-index: ~a key: I-~a" have-db-entry-for-index index))
	        (if have-db-entry-for-index
	          (update-db-index index entry)
	          (new-db-index index entry)))))))

(def (new-index-entry index entry)
  "Add entry to index in global hash"
  (dp (format "new-index-entry: ~a ~a" index entry))
  (unless (hash-key? (hash-get indices-hash index) entry)
    (hash-put! (hash-get indices-hash index) entry #t)))

(def (new-db-index index entry)
  "New index, with entry to db"
  (dp (format "new-db-index: ~a ~a" index entry))
  (let ((current (make-hash-table)))
    (hash-put! current entry #t)
    (hash-put! indices-hash index current)
    (db-put (format "I-~a" index) current)))

(def (update-db-index index entry)
  "Fetch the index from db, then add our new entry, and save."
  (dp (format "update-db-index: ~a ~a" index entry))
  (let ((current (db-get (format "I-~a" index))))
    (hash-put! current entry #t)
    (hash-put! indices-hash index current)
    (dp (format "- ~a:~a length hash: ~a" index entry (hash-length current)))
    (format "I-~a" index) current))

(def (mark-file-processed file)
  (dp "in mark-file-processed")
  (let ((short (get-short file)))
    (format "marking ~A~%" file)
    (db-put (format "F-~a" short) "t")))

(def (read-ct-file file)
  (ensure-db)
  (dp (format "read-ct-file: ~a" file))
  (unless (file-already-processed? file)
    (let ((btime (time->seconds (current-time)))
	        (count 0)
	        (pool []))
      (dp (memory-usage))
      (call-with-input-file file
	      (lambda (file-input)
	        (let ((mytables (hash-ref
			                     (read-json
			                      (open-input-string
			                       (bytes->string
			                        (uncompress file-input))))
			                     'Records)))
	          (for-each
	            (lambda (row)
		            (set! count (+ count 1))
                (dp (format "row-> ~a" (hash->list row)))
                (process-row row))
	            mytables)
	          )))
      (mark-file-processed file)
      (let ((delta (- (time->seconds (current-time)) btime)))
        (displayln "rps: "
                   (float->int (/ count delta )) " size: " count " delta: " delta))
      )))

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

(define 101-fields [
                    'awsRegion
                    'eventID
                    'eventName
                    'eventSource
                    'eventTime
                    'eventType
                    'recipientAccountId
                    'requestID
                    'requestParameters
                    'responseElements
                    'sourceIPAddress
                    'userAgent
                    'userIdentity])

(def (getf field row)
  (hash-get row field))

(def (get-val hcn)
  "Dereference if a valid key in db. otherwise return"
  (dp (format "get-val: ~a string?:~a number?~a" hcn (string? hcn) (number? hcn)))
  (let* ((ret "N/A")
         (hcn-safe (format "~a" hcn)))
    (cond
     ((table? hcn)
      (set! ret hcn))
     ((void? hcn)
      (set! ret 0))
     ((and (string=? "0" hcn-safe))
      (dp "hcn is 0")
      (set! ret "0"))
     ((db-key? hcn-safe)
      (let ((db-val (db-get hcn-safe)))
        (dp (format "db-val: ~a ~a" db-val hcn-safe) )
        (set! ret db-val)
        ))
     (else
      (dp (format "get-val: unknown hcn pattern: ~a" hcn-safe))))
    ret))

(def (add-val val)
  (unless (string? val)
    val)
  (when (string? val)
    (dp (format "add-val: ~a" val))
    (let ((seen (db-key? val))
          (hcn 0))
      (if seen
        (set! hcn (db-get val))
        (begin
          (inc-hc)
          (set! hcn HC)
          (db-put val HC)
          (db-put (format "~a" HC) val)))
      hcn)))

(def (flush-all?)
  (dp (format "write-back-count && max-wb-size ~a ~a" write-back-count max-wb-size))
  (if (> write-back-count max-wb-size)
    (begin
      (displayln "writing.... " write-back-count)
      ;;(type-of (car (##process-statistics)))
      (flush-indices-hash)
      ;;(db-write)
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
      (get-next-id maxid)
      (begin
        ;;(displayln (format "get-next-id: final ~a" maxid))
        maxid))))

(def (inc-hc)
  ;; increment HC to next free id.
  (let ((next (get-next-id HC)))
    (set! HC next)
    (db-put "HC" (format "~a" HC))))

(def (get-next-id-binary max)
  "Starting at zero, double up til we hit unused numeric keys"
  (let lp ((hc max))
    (displayln "gnid: " hc)
    (when (db-key? hc)
      (lp (* 2 hc)))
    hc))

(def (report)
  (indices-report))

(def (indices-report)
  (let ((total 0))
    (hash-for-each
     (lambda (k v)
       (let ((count (hash-length v)))
	       (displayln k ":" count " v: " v " first:" (hash-keys v))
	       (set! total (+ total count))))
     indices-hash)
    (displayln "indicies count total: " total)))

(def (load-indices-hash)
  (dp (format ">-- load-indices-hash: INDICES:~a" (db-key? "INDICES")))
  (inc-hc)
  (if (= (hash-length indices-hash) 0)
    (let ((has-key (db-key? "INDICES")))
      (displayln ">>--- Have INDICES " has-key)
      (if has-key
	      (begin ;; load it up.
	        (dp (format "load-indices-hash records has no INDICES entry"))
	        (let ((indices2 (db-get "INDICES")))
            (dp (hash->list indices2))
	          (for-each
	            (lambda (index)
                (displayln (format "index: ~a" index))
		            (let ((index-int (db-get index)))
		              (hash-put! indices-hash index index-int)))
	            indices2)))))
    (displayln "No INDICES entry. skipping hash loading")))

(def (flush-indices-hash)
  (let ((indices (make-hash-table)))
    (for (index (hash-keys indices-hash))
      (dp (format "fih: index: ~a" index))
      (db-put (format "I-~a" index) (hash-get indices-hash index))
      (hash-put! indices index #t))
    (db-put "INDICES" indices)))

(def (flush-vpc-totals)
  (for (cid (hash-keys vpc-totals))
    (db-put (format "~a" cid) (hash-get vpc-totals cid))))

(def (count-index idx)
  (if (db-key? idx)
    (let* ((entries (hash-keys (db-get idx)))
           (count (length entries)))
      count)))

(def (list-index-entries idx)
  (if (db-key? idx)
    (let ((entries (hash-keys (db-get idx))))
      (if (list? entries)
	      (for-each
	        (lambda (x)
	          (displayln x))
	        (sort! entries eq?))
	      (begin
	        (displayln "did not get list back from entries")
	        (type-of entries))))
    (displayln "no idx found for " idx)))

(def (resolve-records ids)
  (when (list? ids)
    (let ((outs [[ "Date" "Name" "User" "Source" "Hostname" "Type" "Request" "User Agent" "Error Code" "Error Message" ]]))
      (for (id ids)
        (let ((id2 (get-val id)))
          (when (table? id2)
            (let-hash id2
              (set! outs (cons [
                                .?event-time
		                            (get-val-t .?event-name)
		                            (get-val-t .?user)
		                            (get-val-t .?event-source)
		                            (get-val-t .?source-ip-address)
		                            (get-val-t .?event-type)
		                            (get-val-t .?request-parameters)
		                            (get-val-t .?user-agent)
		                            (get-val-t .?error-code)
		                            (get-val-t .?error-message)
                                ] outs))))))
      (style-output outs "org-mode"))))

(def (get-host-name ip)
  (if (pregexp-match "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}" ip)
    (let ((lookup (host-info ip)))
      (if (host-info? lookup)
	      (let ((lookup-name (host-info-name lookup)))
	        lookup-name)))
    ip))

(def (search-event look-for)
  (dp (format "look-for: ~a" look-for))
  (let ((index-name (format "I-~a" look-for)))
    (if (db-key? index-name)
      (let ((matches (hash-keys (db-get index-name))))
	      (resolve-records matches))
      (displayln "Could not find entry in indices-db for " look-for))))

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
        (files (find-files dir
                           (lambda (filename)
                             (and (equal? (path-extension filename) ".gz")
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

(def (summary-by-ip)
  (let (summaries (sort! (hash-keys (db-get "I-source-ip-address")) eq?))
    (for (sumation summaries)
      (summary sumation)
      (displayln ""))))

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
              (db-put (format "H-~a" ip) lookup-name))))))))

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
                (set! username .principalId))) ;; not found go with this for now.
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

(def (search-event-obj look-for)
  (let ((index-name (format "I-~a" look-for)))
    (if (db-key? index-name)
      (let ((matches (hash-keys (db-get index-name))))
        (resolve-records matches))
      (displayln "Could not find entry in indices-db for " look-for))))

(def (inc-hash hashy key)
  (dp (format "~a:~a" (hash->list hashy) key))
  (if (hash-key? hashy key)
    (hash-put! hashy key (+ 1 (hash-get hashy key)))
    (hash-put! hashy key 1)))

(def (summary key)
  (let ((sum (hash))
        (entries (hash-keys (db-get (format "I-~a" key)))))
    (for (entry entries)
      (if (db-key? (format "~a" entry))
        (let ((row (db-get (format "~a" entry))))
          (if (table? row)
            (let-hash row
              (dp (format "~a" (hash->list row)))
              (inc-hash sum (get-val .event-name))
              (inc-hash sum (get-val .event-type))
              (inc-hash sum (get-val .user))
              (inc-hash sum (get-val .source-ip-address))
              (inc-hash sum (get-val .error-message))
              (inc-hash sum (get-val .error-code))
              (inc-hash sum (get-val .aws-region))
              )))
        (displayln "No index for " entry)))

    (display  (format " ~a: " key))
    (if (ip? key) (display (db-get (format "H-~a" key))))
    (hash-for-each
     (lambda (k v)
       (display (format " ~a:~a " k v)))
     sum)))

(def (process-row row)
  (dp (format "process-row: row: ~a" (hash->list row)))
  (let-hash row
    (let*
        ((user (find-user .?userIdentity))
         (req-id (number->string (add-val (or .?requestID .?eventID))))
         (h (hash
             (aws-region (add-val .?awsRegion))
             (error-code (add-val .?errorCode))
             (error-message (add-val .?errorMessage))
             (event-id .?eventID)
             (event-name (add-val .?eventName))
             (event-source (add-val .?eventSource))
             (event-time .?eventTime)
             (event-type (add-val .?eventType))
             (recipient-account-id (add-val .?recipientAccountId))
             (request-parameters .?requestParameters)
             (user (add-val user))
             (response-elements .?responseElements)
             (source-ip-address (add-val .?sourceIPAddress))
             (user-agent (add-val .?userAgent))
             (user-identity .?userIdentity))))

      (dp (hash->list h))
      (set! write-back-count (+ write-back-count 1))
      (dp (format "process-row: doing db-batch on req-id: ~a on hash ~a" req-id (hash->list h)))
      (db-put req-id h)
      (dp (format "------------- end of batch of req-id on hash ----------"))
      (when (string? .?errorCode)
        (add-to-index "errors" .?errorCode)
        (add-to-index .?errorCode req-id))
      (add-to-index "source-ip-address" .sourceIPAddress)
      (add-to-index .sourceIPAddress req-id)
      (add-to-index "users" user)
      (add-to-index user req-id)
      (add-to-index "events" .eventName)
      (add-to-index .eventName req-id)
      (add-to-index "aws-region" .awsRegion)
      (add-to-index .awsRegion req-id))))

(def (add-to-indexes i-hash)
  (when (table? i-hash)
    (hash-for-each
     (lambda (k v)
       (add-to-index k v))
     i-hash)))

(def (get-val-t val)
  (let ((res (get-val val)))
    (if (table? res)
      (hash->list res)
      res)))

;; db stuff

(def (db-batch key value)
  ;;  (if (table? value)
  ;;    (displayln "db-batch:got table in value key:" key " value hash:"  (hash->list value)))
  ;;  (dp (format "db-batch: key: ~a value: ~a" key value))
  (cond
   ((equal? db-type leveldb:)
    (unless (string? key) (dp (format "key: ~a val: ~a" (type-of key) (type-of value))))
    (leveldb-writebatch-put wb key (object->u8vector value)))
   (else
    (displayln "Unknown db-type: " db-type)
    (exit 2))))

(def (db-put key value)
  ;;  (dp (format "db-put: key: ~a val: ~a" key value))
  (cond
   ;; ((equal? db-type lmdb:)
   ;;  (put-lmdb key value))
   ((equal? db-type leveldb:)
    (leveldb-put db key (object->u8vector value)))
   (else
    (displayln "Unknown db-type: " db-type)
    (exit 2))))

(def (ensure-db)
  (unless db
    (set! db (db-open))))

(def (db-open)
  (dp ">-- db-open")
  (cond
   ((equal? db-type leveldb:)
    (let ((db-dir (or (getenv "kunabidb" #f) (format "~a/kunabi-db/" (user-info-home (user-info (user-name)))))))
      (dp (format "db-dir is ~a" db-dir))
      (unless (file-exists? db-dir)
        (create-directory* db-dir))
      (let ((location (format "~a/records" db-dir)))
        (leveldb-open location (leveldb-options
                                paranoid-checks: #t
                                max-open-files: (def-num (getenv "k_max_files" #f))
                                bloom-filter-bits: (def-num (getenv "k_bloom_bits" #f))
                                compression: #t
                                block-size: (def-num (getenv "k_block_size" #f))
                                write-buffer-size: (def-num (getenv "k_write_buffer" (* 1024 1024 16)))
                                lru-cache-capacity: (def-num (getenv "k_lru_cache" 10000)))))))
   (else
    (displayln "Unknown db-type: " db-type)
    (exit 2))))

(def (def-num num)
  (if (string? num)
    (string->number num)
    num))

(def (db-get key)
  (dp (format "db-get: ~a" key))
  (cond
   ;; ((equal? db-type lmdb:)
   ;;  (get-lmdb key))
   ((equal? db-type leveldb:)
    (let ((ret (leveldb-get db (format "~a" key))))
      (if (u8vector? ret)
        (u8vector->object ret)
        "N/A")))
   (else
    (displayln "Unknown db-type: " db-type)
    (exit 2))))


(def (db-key? key)
  (dp (format ">-- db-key? with ~a" key))
  (cond
   ((equal? db-type leveldb:)
    (leveldb-key? db (format "~a" key)))
   (else
    (displayln "Unknown db-type: " db-type)
    (exit 2))))

(def (db-write)
  (dp "in db-write")
  (cond
   ((equal? db-type leveldb:)
    (leveldb-write db wb))
   (else
    (displayln "Unknown db-type: " db-type)
    (exit 2))))

(def (db-close)
  (dp "in db-close")
  (cond
   ;; ((equal? db-type lmdb:)
   ;;  (displayln "db-close lmdb:"))
   ((equal? db-type leveldb:)
    (leveldb-close db))
   (else
    (displayln "Unknown db-type: " db-type)
    (exit 2))))

(def (db-init)
  (dp "in db-init")
  (cond
   ;; ((equal? db-type lmdb:)
   ;;  (displayln "lmdb noop db-init"))
   ((equal? db-type leveldb:)
    (leveldb-writebatch))
   (else
    (displayln "Unknown db-type: " db-type)
    (exit 2))))

;; leveldb stuff
(def (get-leveldb key)
  (displayln "get-leveldb: " key)
  (try
   (let* ((bytes (leveldb-get db (format "~a" key)))
          (val (if (u8vector? bytes)
                 (u8vector->object bytes)
                 nil)))
     val)
   (catch (e)
     (raise e))))

(def (put-leveldb key val)
  (displayln "put-leveldb: " key " " val)
  (try
   (leveldb-put db key (object->u8vector val))
   (catch (e)
     (raise e))))

(def (update-leveldb key val)
  (put-leveldb key val))

(def (remove-leveldb key)
  (dp (format "remove-leveldb: ~a" key)))

(def (compact)
  "Compact some stuff"
  (let* ((itor (leveldb-iterator db))
         (first (get-first-key))
         (last (get-last-key)))
    (displayln "First: " first " Last: " last)
    (leveldb-compact-range db first last)))

(def (count-by-key key)
  "Get a count of how many records are in db"
  (let ((itor (leveldb-iterator db)))
    (leveldb-iterator-seek-first itor)
    (let lp ((count 1))
      (leveldb-iterator-next itor)
      (if (leveldb-iterator-valid? itor)
        (begin
          (if (pregexp-match key (bytes->string (leveldb-iterator-key itor)))
            (lp (1+ count))
            (lp count)))
        count))))

(def (countdb)
  "Get a count of how many records are in db"
  (let ((itor (leveldb-iterator db)))
    (leveldb-iterator-seek-first itor)
    (let lp ((count 1))
      (leveldb-iterator-next itor)
      (if (leveldb-iterator-valid? itor)
        (lp (1+ count))
        count))))

;;(displayln "total: " count)))))

(def (repairdb)
  "Repair the db"
  (let ((db-dir (format "~a/kunabi-db/" (user-info-home (user-info (user-name))))))
    (leveldb-repair-db (format "~a/records" db-dir))))

(def (memo-cid convo)
  (let ((cid 0))
    (if (hash-key? hc-hash convo)
      (begin ;; we are a cache hit
	      (set! cid (hash-get hc-hash convo)))
      (begin ;; no hash entry
	      (inc-hc)
	      (db-batch convo HC)
	      (db-batch (format "~a" HC) convo)
	      ;;(displayln "HC is " HC)
	      (set! cid HC)
	      (hash-put! hc-hash convo cid)
	      (hash-put! hc-hash cid convo)))
    cid))
