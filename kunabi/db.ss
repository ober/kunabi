;; misc db routines

;;;; DB OPERATIONS

(def (db-call operation type key value)
  (cond
   ((equal? operation put:)
    (db-put type key value))
   ((equal? operation get:)
    (db-get type key))
   (else
    (displayln "Unknown operation " operation))))

(def (db-put type key value)
  (cond
   ((equal? type leveldb:)
    (db-put-leveldb key value))
   ((equal? type lmdb:)
    (db-put-lmdb key value))
   (else
    (displayln "Unknown DB type " type))))

(def (db-get type key)
  (cond
   ((equal? type leveldb:)
    (db-get-leveldb key))
   ((equal? type lmdb:)
    (db-get-lmdb key))
   (else
    (displayln "Unknown DB type " type))))

(def (db-open type)
  (dp "in db-open")
  (cond
   ((equal? db-type leveldb:)
    (displayln "can't open leveldb yet"))
    ;;(leveldb-open-db env "kunabi-store"))
   ((equal? db-type lmdb:)
    (lmdb-open-db env "kunabi-store"))
   (else
    (displayln "Unknown db-type: " db-type)
    (exit 2))))

(def (db-init)
  (dp "in db-init")
  (cond
   ((equal? db-type lmdb:)
    (displayln "db-init lmdb noop"))
   (else
    (displayln "Unknown db-type: " db-type)
    (exit 2))))

(def db-dir (or (getenv "KUNABI" #f) ".")) ;;(format "~a/kunabi-db/" (user-info-home (user-info (user-name))))))

(def db-type lmdb:)

(def (db-write db wb)
  (dp "in db-write")
  (cond
   ((equal? db-type lmdb:)
    (displayln "db-write wb lmdb: noop"))
   (else
    (displayln "Unknown db-type: " db-type)
    (exit 2))))

(def (db-close db)
  (dp "in db-close")
  (cond
   ((equal? db-type lmdb:)
    (displayln "db-close lmdb:"))
   (else
    (displayln "Unknown db-type: " db-type)
    (exit 2))))

(def (db-key? db2 key)
  (dp (format "in db-key? db2: ~a key: ~a" db2 key))
  (cond
   ((equal? db-type lmdb:)
    (or (db-get-lmdb key) #f))
   (else
    (displayln "Unknown db-type: " db-type)
    (exit 2))))


(def (db-batch batch key value)
  (cond
   ((equal? db-type lmdb:)
    (db-put-lmdb key value))
   (else
    (displayln "Unknown db-type: " db-type)
    (exit 2))))

(def (get key)
  (dp (format  "get: ~a" key))
  (cond
   ((equal? db-type lmdb:)
    (db-get-lmdb key))
   ((equal? db-type leveldb:)
    (displayln "stub for get in get for leveldb: " key))))
