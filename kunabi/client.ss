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
  :std/db/lmdb
  :std/db/leveldb
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
  :std/text/yaml
  :std/text/zlib
  :ober/oberlib
  )

(export #t)
(declare (not optimize-dead-definitions))
(def version "0.04")

(def program-name "kunabi")
(def config-file "~/.kunabi.yaml")
(def type lmdb:)

(def (dp val)
  (if (getenv "DEBUG" #f)
    (displayln val)))

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

(def (def-num num)
  (if (string? num)
    (string->number num)
    num))


(def max-lru-size (or (getenv "LRU" #f) 10000))
(def use-write-backs #t)
(def lru-hits 0)
(def lru-misses 0)

(setenv "GERBIL_HOME" (format "~a/gerbil" (user-info-home (user-info (user-name)))))

(def hc-hash (make-hash-table))
(def lru-miss-table (make-hash-table))
(def hc-lru (make-lru-cache (def-num max-lru-size)))
(def vpc-totals (make-hash-table))

(def HC 0)

(def write-back-count 0)

(def max-wb-size 1000)

(def indices-hash (make-hash-table))

(def (usage-verb verb)
  (let ((howto (hash-get interactives verb)))
    (displayln "Wrong number of arguments. Usage is:")
    (displayln program-name " " (hash-get howto usage:))
    (exit 2)))

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
  (displayln "list-records not implemented"))

(def (lsv)
  (list-vpc-records))

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

(def (read file)
  (read-ct-file file))

(def (ln)
  (list-index-entries "I-users"))

(def (list-events)
  (list-index-entries "I-events"))

(def (list-regions)
  (list-index-entries "I-aws-region"))

(def (source-ips)
  (list-source-ips))

(def (summaries)
  (summary-by-ip))

(def (vpc file)
  (load-vpc file))

;; (def (vpc file max-wb-size)
;;   (set! max-wb-size (string->number max-wb-size))
;;   (load-vpc file (nth 1 args)))

(def (ct file)
  (load-ct file))

(def (load-ct dir)
  ;;(##gc-report-set! #t)
  (dp (format "load-ct: ~a" dir))
  ;;  (spawn watch-heap!)
  (load-indices-hash)
  (displayln "load-ct post load-indices-hash")
  (let* ((files 0)
	 (rows 0)
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
      (read-ct-file file)
      (flush-all?))
    (hash-for-each
     (lambda (k v)
       (if (> v 1)
	 (displayln k ":" v)))
     lru-miss-table)
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
	  (displayln (format "have-db-entry-for-index: ~a key: I-~a" have-db-entry-for-index index))
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
    (db-batch (format "I-~a" index) current)))

(def (update-db-index index entry)
  "Fetch the index from db, then add our new entry, and save."
  (dp (format "update-db-index: ~a ~a" index entry))
  (let ((current (db-get (format "I-~a" index))))
    (hash-put! current entry #t)
    (hash-put! indices-hash index current)
    (displayln (format "- ~a:~a" index entry) " length hash: " (hash-length current))
    (format "I-~a" index) current))

(def (mark-file-processed file)
  (dp "in mark-file-processed")
  (let ((short (get-short file)))
    (format "marking ~A~%" file)
    (db-put (format "F-~a" short) "t")))

(def (read-ct-file file)
  (dp (format "read-ct-file: ~a" file))
  (unless (file-already-processed? file)
    (let ((lru-hits-begin lru-hits)
	  (lru-misses-begin lru-misses)
	  (btime (time->seconds (current-time)))
	  (count 0)
	  (pool []))
      (dp (format "read-ct-file: ~a" file))
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
		(process-row row))
	      mytables)
	    ;;(for-each
	    ;;(lambda (t)
	    ;;(thread-join! t))
	    ;;pool)
	    )))
      (mark-file-processed file)
      (displayln "rps: "
		 (float->int (/ count (- (time->seconds (current-time)) btime))))
      (print-lru-stats lru-hits-begin lru-misses-begin))))

(def (number-only val)
  (cond ((string? val)
	 (number->string val))
	((number? val)
	 val)))

(def (print-lru-stats begin-hits begin-misses)
  (let* ((lru-hits-file (- lru-hits begin-hits))
	 (lru-misses-file (- lru-misses begin-misses))
	 (lru-totals (+ lru-hits-file lru-misses-file))
	 (lru-hit-percent 0)
	 (lru-miss-percent 0))
    (when (> lru-totals 0)
      (set! lru-hit-percent (float->int (* (/ lru-hits-file lru-totals) 100)))
      (set! lru-miss-percent (float->int (* (/ lru-misses-file lru-totals) 100)))
      (displayln
       " lru % used: "
       (float->int (* (/ (lru-cache-size hc-lru) (def-num max-lru-size)) 100))
       " lru misses: " lru-misses-file
       " lru hits: " lru-hits-file
       " hit %: " lru-hit-percent
       " miss %: " lru-miss-percent))))

(def (get-short str)
  (cond
   ((string-rindex str #\_)
    => (lambda (ix)
	 (cond
	  ((string-index str #\. ix)
	   => (lambda (jx)
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
  "Derefernce if a valid key in db. otherwise return"
  (dp (format "get-val: ~a string?:~a number?~a" hcn (string? hcn) (number? hcn)))
  (let* ((ret "N/A")
	 (hcn-safe (format "~a" hcn))
	 (in-lru (lru-cache-get hc-lru hcn-safe)))
    (cond
     ((table? hcn)
      (set! ret hcn))
     ((void? hcn)
      (set! ret 0))
     ((lru-cache-get hc-lru hcn-safe)
      (dp "in-lru")
      (set! ret in-lru))
     ((and (string=? "0" hcn-safe))
      (dp "hcn is 0")
      (set! ret "0"))
     ((db-key? hcn-safe)
      (let ((db-val (db-get hcn-safe)))
	(dp (format "db-val: ~a ~a" db-val hcn-safe) )
	(set! ret db-val)
	(lru-cache-put! hc-lru hcn-safe db-val)
	))
     (else
      (dp (format "get-val: unknown hcn pattern: ~a" hcn-safe))))
    ret))

(def (miss-add val)
  (if (hash-key? lru-miss-table val)
    (hash-put! lru-miss-table val (+ 1 (hash-get lru-miss-table val)))
    (hash-put! lru-miss-table val 1))
  (set! lru-misses (+ lru-misses 1)))

(def (add-val val)
  "Convert an object to an index id.
  If hash, return 0, as we can't handle those yet"
  (cond
   ((boolean? val)
    0)
   ((void? val)
    0)
   ((table? val)
    (dp (format "Can't have table as key: ~a"  (hash->list val)))
    0)
   ((string? val)
    (let ((hc-lru-entry (lru-cache-get hc-lru val))
	  (hcn 0))
      (if hc-lru-entry
	(begin ;; in cache
	  (set! lru-hits (+ lru-hits 1))
	  (set! hcn hc-lru-entry))
	(begin ;; lru miss. if in db, fetch, push onto lru, if not, add to db, push to lru
	  (dp (format "add-val: ~a " val))
	  (miss-add val)
	  ;;(displayln val)
	  (set! hcn (add-val-db-lru val))))
      hcn))
   (else
    (dp (type-of val))
    0)))

(def (add-val-db-lru val)
  (let ((seen (db-key? val))
	(hcn 0))
    (if seen
      (set! hcn (db-get val))
      (begin ;; not seen. need to bump HC and use new HC
	(dp (format "db miss: ~a" val))
	(inc-hc)
	(set! hcn HC)
	(db-batch val HC)
	(db-batch (format "~a" HC) val)))
    (lru-cache-put! hc-lru val hcn)
    hcn))

(def (add-val-db val)
  (set! db-type lmdb:)
  (displayln "add-val-db: val: " val " db-type: " db-type)
  (let ((seen (db-key? val))
	(hcn 0))
    (if seen
      (set! hcn (db-get val))
      (begin ;; not seen. need to bump HC and use new HC
	(inc-hc)
	(set! hcn HC)
	(db-batch val HC)
	))
    hcn))

(def (flush-all?)
  (dp (format "write-back-count && max-wb-size ~a ~a" write-back-count max-wb-size))
  (if (> write-back-count max-wb-size)
    (begin
      (displayln "writing.... " write-back-count)
      ;;(type-of (car (##process-statistics)))
      (time (flush-indices-hash))
      (time (db-write))
      (set! write-back-count 0))))

(def (get-next-id max)
  (let ((maxid (1+ max)))
    (if (db-key? (format "~a" maxid))
      (get-next-id maxid)
      maxid)))

(def (inc-hc)
  ;; increment HC to next free id.
  (set! HC (get-next-id HC))
  (db-put "HC" (format "~a" HC)))

(def (indices-report)
  (let ((total 0))
    (hash-for-each
     (lambda (k v)
       (let ((count (hash-length v)))
	 (displayln k ":" count " v: " v " first:" (hash-keys v))
	 (set! total (+ total count))))
     indices-hash)
    (displayln "idicies count total: " total)))

(def (load-indices-hash)
  (dp (format "in load-indices-hash: INDICES:~a" (db-key? "INDICES")))
  (inc-hc)
  (if (= (hash-length indices-hash) 0)
    (let ((has-key (db-key? "INDICES")))
      (displayln "has-key " has-key)
      (if has-key
	(begin ;; load it up.
	  (dp (format "load-indices-hash records has no INDICES entry"))
	  (let ((indices (db-get "INDICES")))
	    (dp (hash->list indices))
	    (for-each
	      (lambda (index)
		(displayln (format "index: ~a" index))
		(let ((index-int (db-get index)))
		  (hash-put! indices-hash index index-int)))
	      indices)))))
    (displayln "No INDICES entry. skipping hash loading")))

(def (flush-indices-hash)
  (let ((indices (make-hash-table)))
    (for (index (hash-keys indices-hash))
      (db-batch (format "I-~a" index) (hash-get indices-hash index))
      (hash-put! indices index #t))
    (db-put "INDICES" indices)))

(def (flush-vpc-totals)
  (for (cid (hash-keys vpc-totals))
    (db-batch (format "~a" cid) (hash-get vpc-totals cid))))


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
    (displayln "| date                 | name      | user   |  source | hostname| type| request| user-agent| error-code | error-messages |")
    (displayln "|----------------------+-----------+-------------------+--------------+------------+--------------------+----------------------+------------+---------------|")
    (for (id ids)
      (let ((id2 (get-val id)))
        ;;	    (displayln "resolve-records: id: " id " id2: " (hash->list id2))
        (if (table? id2)
          (print-record id2))))))

(def (get-host-name ip)
  (if (pregexp-match "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}" ip)
    (let ((lookup (host-info ip)))
      (if (host-info? lookup)
	(let ((lookup-name (host-info-name lookup)))
	  lookup-name)))
    ip))

(def (print-record row)
  (if (table? row)
    (let-hash row
      (displayln "|"
		 .event-time
		 "|"
		 (get-val-t .?event-name)
		 "|"
		 (get-val-t .?user)
		 "|"
		 (get-val-t .?event-source)
		 "|"
		 (get-val-t .?source-ip-address)
		 "|"
		 (get-val-t .?event-type)
		 "|"
		 (get-val-t .?request-parameters)
		 "|"
		 (get-val-t .?user-agent)
		 "|"
		 (get-val-t .?error-code)
		 "|"
		 (get-val-t .?error-message)
		 "|"
		 ))))

(def (search-event look-for)
  (dp (format "look-for: ~a" look-for))
  (let ((index-name (format "I-~a" look-for)))
    (if (db-key? index-name)
      (let ((matches (hash-keys (db-get index-name))))
	;;	(displayln matches)
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
      (hash-put! vpc-totals cid (+ (def-num total) (def-num bytez))))
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
  (let ((files 0)
	(rows 0)
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
             ((string=? "IAMUser" type)
              (set! username .userName))
             ((string=? "AWSAccount" type)
              (set! username (format "~a-~a" .accountId .principalId)))
             ((string=? "AssumedRole" type)
              (if (hash-key? ui 'sessionContext)
                (let-hash
                    .sessionContext
                  (let-hash
                      .sessionIssuer
                    (set! username .userName)))
                (begin ;; not found
                  (displayln "could not find username. " (hash->list ui)))))
             ((string=? "AWSService" type)
              (set! username (hash-get ui 'invokedBy)))
             ((string=? "Root" type)
              (set! username (format "~a invokedBy: ~a" (hash-get ui 'userName) (hash-get ui 'invokedBy))))
             ((string=? "FederatedUser" type)
              (let-hash ui
                (let-hash .sessionContext
                  (set! username (hash-ref .sessionIssuer 'userName)))))
             (else
              (set! username (format "Unknown Type: ~a" (stringify-hash ui)))))
            (displayln "error: type :" type " not found in ui" (stringify-hash ui))))))
    username))

(def vpc-fields [
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
                 ])

(def (search-event-obj look-for)
  (let ((index-name (format "I-~a" look-for)))
    (if (db-key? index-name)
      (let ((matches (hash-keys (db-get index-name))))
        (resolve-records matches))
      (displayln "Could not find entry in indices-db for " look-for))))

(def (float->int num)
  (inexact->exact
   (round num)))

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
         (req-id (number->string (add-val-db (or .?requestID .?eventID))))
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

      (set! write-back-count (+ write-back-count 1))
      (dp (format "process-row: doing db-batch on req-id: ~a on hash ~a" req-id (hash->list h)))
      (spawn
       (lambda ()
         (db-batch req-id h)
         (dp (format "------------- end of batch of req-id on hash ----------"))
         (when (string? .?errorCode)
           (add-to-indexes
            (hash ("errors" .?errorCode)
                  (.?errorCode req-id))))
         (add-to-indexes
          (hash ("source-ip-address" .sourceIPAddress)
                (.sourceIPAddress req-id)
                ("users" user)
                (user req-id)
                ("events" .eventName)
                (.eventName req-id)
                ("aws-region" .awsRegion)
                (.awsRegion req-id))))))))

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
