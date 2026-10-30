// Package sink contains the output paths for captured frames: ZEP over UDP
// and a direct pcapng capture file.
package sink

// Sink accepts complete ZEP v2 datagrams.
type Sink interface {
	Write(packet []byte) error
	Close() error
}
