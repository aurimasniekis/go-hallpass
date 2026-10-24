package store

type Queries struct{}

func (q *Queries) Insert() error { return nil }

func (q *Queries) AfterCommit(fn func()) {}

type Writer struct{}

func (w *Writer) Tx(fn func(q *Queries) error) error { return fn(&Queries{}) }

type Other struct{}

func (o *Other) Tx(fn func() error) error { return fn() }

// Tx is the transaction handle passed to transaction bodies and helpers.
type Tx struct{ Q *Queries }

func (w *Writer) TxNamed(name string, fn func(tx *Tx) error) error { return fn(&Tx{}) }
