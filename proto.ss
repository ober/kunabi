;;; -*- Gerbil -*-
(import :std/actor)
(export #t)

;; A protocol for key-value stores
;; (get key)      -- retrieve object associated with key, or #f if not found
;; (ref key)      -- like get, but result in an exception if not foound
;; (put! key val) -- put an object for a key to the store
;; (remove! key)  -- remove a key
;; (update key val) -- add a key to an existing val hash

(defproto kunabi-store
  (get key)
  (ref key)
  (process-row key)
  (update! key val)
  (put! key val)
  (remove! key))

;; bind the protocol for the kvstore actor
(bind-protocol! 'kunabi-store kunabi-store::proto)
