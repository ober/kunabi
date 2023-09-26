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
  :clan/db/leveldb
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


(def vpc-totals (make-hash-table))

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

(def (lvf file)
  (read-vpc-file file))

(def (vpc file)
  (load-vpc file))

(def (flush-vpc-totals)
  (for (cid (hash-keys vpc-totals))
    (db-batch (format "~a" cid) (hash-get vpc-totals cid))))

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
