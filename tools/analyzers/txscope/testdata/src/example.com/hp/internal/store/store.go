package store

type Queries struct{}

func (q *Queries) Insert() error { return nil }

type Writer struct{}

func (w *Writer) Tx(fn func(q *Queries) error) error { return fn(&Queries{}) }

type Other struct{}

func (o *Other) Tx(fn func() error) error { return fn() }
