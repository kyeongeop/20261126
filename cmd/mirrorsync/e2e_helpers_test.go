package main

import (
	"net"
	"time"
)

func timeNow() time.Time { return time.Now() }
func dialTimeout(network, addr string, d time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, addr, d)
}
func sleep100() { time.Sleep(100 * time.Millisecond) }
