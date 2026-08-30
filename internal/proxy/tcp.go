package proxy

import (
	"io"
	"net"
	"sync"
	"time"
)

const copyBufSize = 32 * 1024

// Relay copies both directions until one side fails or idle timeout fires.
// idle <= 0 disables the idle timer.
func Relay(a, b net.Conn, idle time.Duration) error {
	errc := make(chan error, 2)
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}
	go func() { errc <- pipe(a, b, idle) }()
	go func() { errc <- pipe(b, a, idle) }()
	err := <-errc
	closeBoth()
	<-errc
	if err == io.EOF {
		return nil
	}
	return err
}

func pipe(dst net.Conn, src net.Conn, idle time.Duration) error {
	buf := make([]byte, copyBufSize)
	for {
		if idle > 0 {
			_ = src.SetReadDeadline(time.Now().Add(idle))
		}
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			return err
		}
	}
}
