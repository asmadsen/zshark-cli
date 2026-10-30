package sink_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	"zshark/internal/sink"
)

func TestUDPWrite(t *testing.T) {
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	u, err := sink.NewUDP(listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	packet := []byte("EX\x02\x01test")
	if err := u.Write(packet); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, _, err := listener.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], packet) {
		t.Errorf("datagram = %x, want %x", buf[:n], packet)
	}
}

func TestNewUDPInvalidDestination(t *testing.T) {
	if _, err := sink.NewUDP("not-an-address"); err == nil {
		t.Fatal("invalid destination accepted")
	}
}
