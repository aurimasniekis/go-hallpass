package a

import (
	"net"
	"os"
	"time"

	"example.com/hp/internal/notify"
	"example.com/hp/internal/store"
)

func bad(w *store.Writer, ch chan int, f *os.File) error {
	return w.Tx(func(q *store.Queries) error {
		_, _ = net.Dial("tcp", "x:1") // want `call to net.Dial inside store transaction`
		time.Sleep(time.Second)       // want `time.Sleep inside store transaction`
		_ = f.Sync()                  // want `file fsync inside store transaction`
		_ = notify.Send()             // want `call to example.com/hp/internal/notify.Send inside store transaction`
		<-ch                          // want `channel receive inside store transaction`
		ch <- 1                       // want `channel send inside store transaction`
		select {                      // want `select statement inside store transaction`
		default:
		}
		return q.Insert()
	})
}

func good(w *store.Writer, ch chan int) error {
	if err := w.Tx(func(q *store.Queries) error { return q.Insert() }); err != nil {
		return err
	}
	<-ch
	return notify.Send()
}
