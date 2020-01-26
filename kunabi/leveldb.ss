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

(def (db-get-leveldb key)
  (displayln "place holder"))
