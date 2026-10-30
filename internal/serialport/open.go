package serialport

import (
	"fmt"
	"io"
	"time"

	"go.bug.st/serial"
)

// ReadTimeout keeps the capture loop responsive to signals and shutdown while
// preserving streaming reads.
const ReadTimeout = 200 * time.Millisecond

// Open opens path at 38400 8N1 with no flow control.
func Open(path string) (serial.Port, error) {
	port, err := serial.Open(path, &serial.Mode{
		BaudRate: BaudRate,
		DataBits: 8,
		Parity:   serial.NoParity,
		StopBits: serial.OneStopBit,
	})
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if err := port.SetReadTimeout(ReadTimeout); err != nil {
		_ = port.Close()
		return nil, fmt.Errorf("set read timeout on %s: %w", path, err)
	}
	return port, nil
}

// WriteCommand sends one newline-framed command and checks for a short write.
func WriteCommand(port serial.Port, command []byte) error {
	n, err := port.Write(command)
	if err != nil {
		return err
	}
	if n != len(command) {
		return io.ErrShortWrite
	}
	return nil
}
