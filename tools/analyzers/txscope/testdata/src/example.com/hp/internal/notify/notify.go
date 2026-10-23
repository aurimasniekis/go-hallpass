package notify

import "example.com/hp/internal/store"

func Send() error { return nil }

// EnqueueTx is a transaction-scoped helper (outbox pattern): allowed inside a transaction.
func EnqueueTx(q *store.Queries) error { return q.Insert() }
