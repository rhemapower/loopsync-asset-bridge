;; loopsync-bridge
;; Manages cross-chain asset synchronization and verification for the LoopSync Asset Bridge
;; This contract serves as the central hub for transferring assets between Stacks and external chains
;; through secure locking, releasing, and verification mechanisms.

;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ASSET-NOT-SUPPORTED (err u101))
(define-constant ERR-INSUFFICIENT-BALANCE (err u102))
(define-constant ERR-INVALID-PROOF (err u103))
(define-constant ERR-EXCEEDED-LIMITS (err u104))
(define-constant ERR-TIMELOCK-ACTIVE (err u105))
(define-constant ERR-ALREADY-PROCESSED (err u106))
(define-constant ERR-INVALID-AMOUNT (err u107))
(define-constant ERR-INVALID-DESTINATION (err u108))
(define-constant ERR-CHAIN-NOT-SUPPORTED (err u109))
(define-constant ERR-INVALID-PARAMS (err u110))

;; Data variables
(define-data-var contract-owner principal tx-sender)
(define-data-var paused bool false)
(define-data-var nonce uint u0)

;; Asset registry - maps asset identifier to asset info
(define-map supported-assets 
  { asset-id: (string-ascii 32) }
  {
    asset-type: (string-ascii 10), ;; "ft", "nft", "stx"
    asset-contract: principal,
    conversion-rate: uint,
    daily-limit: uint,
    min-amount: uint,
    max-amount: uint,
    timelock-threshold: uint,
    timelock-blocks: uint,
    is-active: bool
  }
)

;; Chain registry - tracks supported external chains
(define-map supported-chains
  { chain-id: (string-ascii 10) }
  {
    name: (string-ascii 32),
    verification-method: (string-ascii 20), ;; "merkle", "signature", "oracle"
    required-confirmations: uint,
    is-active: bool
  }
)

;; Bridge state - tracks locked assets on Stacks side
(define-map bridge-balances
  { asset-id: (string-ascii 32) }
  { total-locked: uint }
)

;; Transaction history - records all sync operations
(define-map sync-transactions
  { tx-id: (string-ascii 64) }
  {
    initiator: principal,
    asset-id: (string-ascii 32),
    amount: uint,
    source-chain: (string-ascii 10),
    destination-chain: (string-ascii 10),
    destination-address: (string-ascii 64),
    block-height: uint,
    status: (string-ascii 10), ;; "pending", "completed", "failed"
    timestamp: uint
  }
)

;; Timelock registry - tracks timelocked transfers
(define-map timelocked-transfers
  { tx-id: (string-ascii 64) }
  {
    initiator: principal,
    asset-id: (string-ascii 32),
    amount: uint,
    destination-chain: (string-ascii 10),
    destination-address: (string-ascii 64),
    unlock-height: uint,
    is-released: bool
  }
)

;; Processed proofs - prevents replay attacks
(define-map processed-proofs
  { proof-id: (string-ascii 64) }
  { processed: bool }
)

;; Daily transfer tracking
(define-map daily-transfers
  { asset-id: (string-ascii 32), day: uint }
  { total-amount: uint }
)

;; Administrator management
(define-map administrators
  { admin: principal }
  { is-active: bool }
)

;; Private functions

;; Generate a unique transaction ID
(define-private (generate-tx-id)
  (begin
    (var-set nonce (+ (var-get nonce) u1))
    (concat (concat (to-ascii (var-get nonce)) "-") 
            (to-ascii (as-max-len? (unwrap-panic (to-consensus-buff? tx-sender)) u32)))
  )
)

;; Get current day number (for daily limits)
(define-private (get-current-day)
  (/ burn-block-height u144) ;; ~144 blocks per day
)

;; Update daily transfer amounts
(define-private (update-daily-transfer (asset-id (string-ascii 32)) (amount uint))
  (let ((current-day (get-current-day))
        (current-total (default-to u0 
                        (get total-amount 
                          (map-get? daily-transfers {asset-id: asset-id, day: current-day})))))
    (map-set daily-transfers 
      {asset-id: asset-id, day: current-day}
      {total-amount: (+ current-total amount)})
  )
)

;; Check if a transfer would exceed daily limits
(define-private (check-daily-limit (asset-id (string-ascii 32)) (amount uint))
  (let ((asset-info (unwrap! (map-get? supported-assets {asset-id: asset-id}) ERR-ASSET-NOT-SUPPORTED))
        (current-day (get-current-day))
        (current-total (default-to u0 
                        (get total-amount 
                          (map-get? daily-transfers {asset-id: asset-id, day: current-day})))))
    (if (<= (+ current-total amount) (get daily-limit asset-info))
      (ok true)
      ERR-EXCEEDED-LIMITS)
  )
)

;; Check if an amount is within allowed range
(define-private (check-amount-limits (asset-id (string-ascii 32)) (amount uint))
  (let ((asset-info (unwrap! (map-get? supported-assets {asset-id: asset-id}) ERR-ASSET-NOT-SUPPORTED)))
    (if (and (>= amount (get min-amount asset-info))
             (<= amount (get max-amount asset-info)))
      (ok true)
      ERR-INVALID-AMOUNT)
  )
)

;; Check if a chain is supported
(define-private (check-chain-supported (chain-id (string-ascii 10)))
  (let ((chain-info (map-get? supported-chains {chain-id: chain-id})))
    (if (and (is-some chain-info)
             (get is-active (unwrap-panic chain-info)))
      (ok true)
      ERR-CHAIN-NOT-SUPPORTED)
  )
)

;; Verify if a timelock should be applied
(define-private (check-timelock (asset-id (string-ascii 32)) (amount uint))
  (let ((asset-info (unwrap! (map-get? supported-assets {asset-id: asset-id}) ERR-ASSET-NOT-SUPPORTED)))
    (if (>= amount (get timelock-threshold asset-info))
      (some (get timelock-blocks asset-info))
      none)
  )
)

;; Record a sync transaction in history
(define-private (record-transaction (tx-id (string-ascii 64)) 
                                   (asset-id (string-ascii 32))
                                   (amount uint)
                                   (source-chain (string-ascii 10))
                                   (destination-chain (string-ascii 10))
                                   (destination-address (string-ascii 64))
                                   (status (string-ascii 10)))
  (map-set sync-transactions
    {tx-id: tx-id}
    {
      initiator: tx-sender,
      asset-id: asset-id,
      amount: amount,
      source-chain: source-chain,
      destination-chain: destination-chain,
      destination-address: destination-address,
      block-height: block-height,
      status: status,
      timestamp: burn-block-height
    }
  )
)

;; Update bridge balances when locking/unlocking assets
(define-private (update-bridge-balance (asset-id (string-ascii 32)) (amount uint) (is-lock bool))
  (let ((current-balance (default-to {total-locked: u0} 
                          (map-get? bridge-balances {asset-id: asset-id})))
        (new-balance (if is-lock
                       (+ (get total-locked current-balance) amount)
                       (- (get total-locked current-balance) amount))))
    (map-set bridge-balances
      {asset-id: asset-id}
      {total-locked: new-balance})
  )
)

;; Check if caller is authorized administrator
(define-private (is-authorized)
  (or (is-eq tx-sender (var-get contract-owner))
      (default-to false (get is-active (map-get? administrators {admin: tx-sender}))))
)

;; Validate a cryptographic proof from external chain
;; This is a simplified implementation - real implementation would include cryptographic verification
(define-private (verify-external-proof (proof-data (string-ascii 64)) 
                                      (chain-id (string-ascii 10))
                                      (asset-id (string-ascii 32))
                                      (amount uint)
                                      (source-address (string-ascii 64))
                                      (destination-address (string-ascii 64)))
  ;; In a production contract, this would contain complex logic to verify
  ;; merkle proofs, signatures, or oracle data depending on the chain
  (if (map-get? processed-proofs {proof-id: proof-data})
    ERR-ALREADY-PROCESSED
    (ok true))
)

;; Transfer fungible tokens to the contract (lock)
(define-private (lock-ft (asset-contract principal) (amount uint))
  (ft-transfer? asset-contract amount tx-sender (as-contract tx-sender))
)

;; Transfer fungible tokens from the contract (release)
(define-private (release-ft (asset-contract principal) (amount uint) (recipient principal))
  (as-contract (ft-transfer? asset-contract amount tx-sender recipient))
)

;; Transfer STX to the contract (lock)
(define-private (lock-stx (amount uint))
  (stx-transfer? amount tx-sender (as-contract tx-sender))
)

;; Transfer STX from the contract (release)
(define-private (release-stx (amount uint) (recipient principal))
  (as-contract (stx-transfer? amount tx-sender recipient))
)

;; Read-only functions

;; Get asset information
(define-read-only (get-asset-info (asset-id (string-ascii 32)))
  (map-get? supported-assets {asset-id: asset-id})
)

;; Get chain information
(define-read-only (get-chain-info (chain-id (string-ascii 10)))
  (map-get? supported-chains {chain-id: chain-id})
)

;; Get transaction details
(define-read-only (get-transaction (tx-id (string-ascii 64)))
  (map-get? sync-transactions {tx-id: tx-id})
)

;; Get timelock information
(define-read-only (get-timelock-info (tx-id (string-ascii 64)))
  (map-get? timelocked-transfers {tx-id: tx-id})
)

;; Check if a proof has been processed
(define-read-only (is-proof-processed (proof-id (string-ascii 64)))
  (is-some (map-get? processed-proofs {proof-id: proof-id}))
)

;; Get total locked amount of an asset
(define-read-only (get-total-locked (asset-id (string-ascii 32)))
  (default-to {total-locked: u0} (map-get? bridge-balances {asset-id: asset-id}))
)

;; Get remaining daily transfer limit
(define-read-only (get-remaining-daily-limit (asset-id (string-ascii 32)))
  (let ((asset-info (map-get? supported-assets {asset-id: asset-id}))
        (current-day (get-current-day))
        (current-total (default-to u0 
                        (get total-amount 
                          (map-get? daily-transfers {asset-id: asset-id, day: current-day})))))
    (if (is-some asset-info)
      (- (get daily-limit (unwrap-panic asset-info)) current-total)
      u0)
  )
)

;; Check if an administrator is active
(define-read-only (is-admin (address principal))
  (default-to false (get is-active (map-get? administrators {admin: address})))
)

;; Public functions

;; Deposit assets from Stacks to bridge to external chain
(define-public (deposit-to-external-chain 
                (asset-id (string-ascii 32))
                (amount uint)
                (destination-chain (string-ascii 10))
                (destination-address (string-ascii 64)))
  (let ((asset-info (unwrap! (map-get? supported-assets {asset-id: asset-id}) ERR-ASSET-NOT-SUPPORTED))
        (tx-id (generate-tx-id))
        (timelock-blocks (check-timelock asset-id amount)))
    
    ;; Validation checks
    (asserts! (not (var-get paused)) ERR-NOT-AUTHORIZED)
    (asserts! (get is-active asset-info) ERR-ASSET-NOT-SUPPORTED)
    (asserts! (> amount u0) ERR-INVALID-AMOUNT)
    (try! (check-chain-supported destination-chain))
    (try! (check-amount-limits asset-id amount))
    (try! (check-daily-limit asset-id amount))
    
    ;; Apply timelock if needed
    (if (is-some timelock-blocks)
      (begin
        (map-set timelocked-transfers
          {tx-id: tx-id}
          {
            initiator: tx-sender,
            asset-id: asset-id,
            amount: amount,
            destination-chain: destination-chain,
            destination-address: destination-address,
            unlock-height: (+ block-height (unwrap-panic timelock-blocks)),
            is-released: false
          })
        (record-transaction tx-id asset-id amount "stacks" destination-chain destination-address "pending")
        (ok tx-id))
      
      ;; Process immediately if no timelock
      (begin
        ;; Lock assets based on type
        (match (get asset-type asset-info)
          "ft" (try! (lock-ft (get asset-contract asset-info) amount))
          "stx" (try! (lock-stx amount))
          (err ERR-ASSET-NOT-SUPPORTED)
        )
        
        ;; Update state and records
        (update-bridge-balance asset-id amount true)
        (update-daily-transfer asset-id amount)
        (record-transaction tx-id asset-id amount "stacks" destination-chain destination-address "completed")
        
        (ok tx-id)
      ))
  )
)

;; Release a timelocked deposit
(define-public (release-timelocked-deposit (tx-id (string-ascii 64)))
  (let ((timelock-info (unwrap! (map-get? timelocked-transfers {tx-id: tx-id}) ERR-INVALID-PARAMS))
        (asset-info (unwrap! (map-get? supported-assets {asset-id: (get asset-id timelock-info)}) ERR-ASSET-NOT-SUPPORTED)))
    
    ;; Check conditions
    (asserts! (not (var-get paused)) ERR-NOT-AUTHORIZED)
    (asserts! (is-eq (get initiator timelock-info) tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (not (get is-released timelock-info)) ERR-ALREADY-PROCESSED)
    (asserts! (>= block-height (get unlock-height timelock-info)) ERR-TIMELOCK-ACTIVE)
    
    ;; Lock assets based on type
    (match (get asset-type asset-info)
      "ft" (try! (lock-ft (get asset-contract asset-info) (get amount timelock-info)))
      "stx" (try! (lock-stx (get amount timelock-info)))
      (err ERR-ASSET-NOT-SUPPORTED)
    )
    
    ;; Update state and records
    (map-set timelocked-transfers
      {tx-id: tx-id}
      (merge timelock-info {is-released: true}))
    
    (update-bridge-balance (get asset-id timelock-info) (get amount timelock-info) true)
    (update-daily-transfer (get asset-id timelock-info) (get amount timelock-info))
    
    (map-set sync-transactions
      {tx-id: tx-id}
      (merge (unwrap-panic (map-get? sync-transactions {tx-id: tx-id}))
            {status: "completed", block-height: block-height}))
    
    (ok true)
  )
)

;; Cancel a timelocked deposit
(define-public (cancel-timelocked-deposit (tx-id (string-ascii 64)))
  (let ((timelock-info (unwrap! (map-get? timelocked-transfers {tx-id: tx-id}) ERR-INVALID-PARAMS)))
    
    ;; Check conditions
    (asserts! (is-eq (get initiator timelock-info) tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (not (get is-released timelock-info)) ERR-ALREADY-PROCESSED)
    
    ;; Update records
    (map-set timelocked-transfers
      {tx-id: tx-id}
      (merge timelock-info {is-released: true}))
    
    (map-set sync-transactions
      {tx-id: tx-id}
      (merge (unwrap-panic (map-get? sync-transactions {tx-id: tx-id}))
            {status: "failed", block-height: block-height}))
    
    (ok true)
  )
)

;; Process deposit from external chain to mint/release on Stacks
(define-public (process-external-deposit
                (proof-data (string-ascii 64))
                (chain-id (string-ascii 10))
                (asset-id (string-ascii 32))
                (amount uint)
                (source-address (string-ascii 64))
                (recipient principal))
  (let ((asset-info (unwrap! (map-get? supported-assets {asset-id: asset-id}) ERR-ASSET-NOT-SUPPORTED))
        (tx-id (generate-tx-id)))
    
    ;; Validation checks
    (asserts! (not (var-get paused)) ERR-NOT-AUTHORIZED)
    (asserts! (get is-active asset-info) ERR-ASSET-NOT-SUPPORTED)
    (asserts! (> amount u0) ERR-INVALID-AMOUNT)
    (try! (check-chain-supported chain-id))
    (try! (check-amount-limits asset-id amount))
    (try! (check-daily-limit asset-id amount))
    
    ;; Verify proof from external chain
    (try! (verify-external-proof proof-data chain-id asset-id amount source-address 
                                (unwrap-panic (to-consensus-buff? recipient))))
    
    ;; Mark proof as processed to prevent replay
    (map-set processed-proofs {proof-id: proof-data} {processed: true})
    
    ;; Release assets based on type
    (match (get asset-type asset-info)
      "ft" (try! (release-ft (get asset-contract asset-info) amount recipient))
      "stx" (try! (release-stx amount recipient))
      (err ERR-ASSET-NOT-SUPPORTED)
    )
    
    ;; Update state and records
    (update-bridge-balance asset-id amount false)
    (update-daily-transfer asset-id amount)
    (record-transaction tx-id asset-id amount chain-id "stacks" 
                        (unwrap-panic (to-consensus-buff? recipient)) "completed")
    
    (ok tx-id)
  )
)

;; Admin functions

;; Add or update a supported asset
(define-public (set-supported-asset
                (asset-id (string-ascii 32))
                (asset-type (string-ascii 10))
                (asset-contract principal)
                (conversion-rate uint)
                (daily-limit uint)
                (min-amount uint)
                (max-amount uint)
                (timelock-threshold uint)
                (timelock-blocks uint)
                (is-active bool))
  (begin
    (asserts! (is-authorized) ERR-NOT-AUTHORIZED)
    (asserts! (or (is-eq asset-type "ft") (is-eq asset-type "nft") (is-eq asset-type "stx")) ERR-INVALID-PARAMS)
    
    (map-set supported-assets
      {asset-id: asset-id}
      {
        asset-type: asset-type,
        asset-contract: asset-contract,
        conversion-rate: conversion-rate,
        daily-limit: daily-limit,
        min-amount: min-amount,
        max-amount: max-amount,
        timelock-threshold: timelock-threshold,
        timelock-blocks: timelock-blocks,
        is-active: is-active
      })
    (ok true)
  )
)

;; Add or update a supported chain
(define-public (set-supported-chain
                (chain-id (string-ascii 10))
                (name (string-ascii 32))
                (verification-method (string-ascii 20))
                (required-confirmations uint)
                (is-active bool))
  (begin
    (asserts! (is-authorized) ERR-NOT-AUTHORIZED)
    
    (map-set supported-chains
      {chain-id: chain-id}
      {
        name: name,
        verification-method: verification-method,
        required-confirmations: required-confirmations,
        is-active: is-active
      })
    (ok true)
  )
)

;; Add or remove an administrator
(define-public (set-administrator (admin principal) (is-active bool))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
    
    (map-set administrators
      {admin: admin}
      {is-active: is-active})
    (ok true)
  )
)

;; Pause or unpause the contract
(define-public (set-paused (paused-state bool))
  (begin
    (asserts! (is-authorized) ERR-NOT-AUTHORIZED)
    (var-set paused paused-state)
    (ok true)
  )
)

;; Transfer contract ownership
(define-public (transfer-ownership (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
    (var-set contract-owner new-owner)
    (ok true)
  )
)