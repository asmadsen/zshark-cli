package sink

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// ErrBackoff means the sink is waiting before its next reconnect attempt and
// the packet was dropped.
var ErrBackoff = errors.New("udp sink is waiting to reconnect")

const (
	initialBackoff = time.Second
	maxBackoff     = 30 * time.Second
)

// UDP sends ZEP datagrams to a single destination. It reconnects with
// exponential backoff after a socket error instead of terminating the capture.
type UDP struct {
	mu      sync.Mutex
	dest    string
	conn    *net.UDPConn
	backoff time.Duration
	nextTry time.Time
}

// NewUDP resolves dest and creates the initial UDP socket.
func NewUDP(dest string) (*UDP, error) {
	u := &UDP{dest: dest, backoff: initialBackoff}
	if err := u.connect(); err != nil {
		return nil, err
	}
	return u, nil
}

func (u *UDP) connect() error {
	addr, err := net.ResolveUDPAddr("udp", u.dest)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", u.dest, err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", u.dest, err)
	}
	u.conn = conn
	u.backoff = initialBackoff
	u.nextTry = time.Time{}
	return nil
}

// Write sends one datagram. It is safe to call from one capture goroutine.
func (u *UDP) Write(packet []byte) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	now := time.Now()
	if u.conn == nil {
		if now.Before(u.nextTry) {
			return ErrBackoff
		}
		if err := u.connect(); err != nil {
			u.scheduleReconnect(now)
			return err
		}
	}
	if _, err := u.conn.Write(packet); err != nil {
		_ = u.conn.Close()
		u.conn = nil
		u.scheduleReconnect(now)
		return fmt.Errorf("send ZEP: %w", err)
	}
	return nil
}

func (u *UDP) scheduleReconnect(now time.Time) {
	u.nextTry = now.Add(u.backoff)
	u.backoff *= 2
	if u.backoff > maxBackoff {
		u.backoff = maxBackoff
	}
}

// Close releases the UDP socket.
func (u *UDP) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.conn == nil {
		return nil
	}
	err := u.conn.Close()
	u.conn = nil
	return err
}
