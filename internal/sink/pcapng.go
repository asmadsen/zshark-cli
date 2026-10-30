package sink

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"

	"zshark/internal/zep"
)

const (
	pcapngSHBType = 0x0a0d0d0a
	pcapngIDBType = 1
	pcapngEPBType = 6
	pcapngBOM     = 0x1a2b3c4d
	pcapngVersion = 1
	pcapngSnapLen = 65535
	linkTypeEther = 1

	zepPort    = 17754
	zepSrcPort = 48311
)

var (
	ethDst = [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	ethSrc = [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	ipSrc  = net.IPv4(192, 168, 20, 234)
	ipDst  = net.IPv4(192, 168, 20, 1)
)

// Pcapng writes a pcapng capture with one Ethernet/IPv4/UDP-wrapped ZEP
// datagram per enhanced packet block.
type Pcapng struct {
	buf    *bufio.Writer
	closer io.Closer
	closed bool
}

// NewPcapng writes the section header and interface description and returns a
// writer for ZEP datagrams. The caller keeps ownership of w.
func NewPcapng(w io.Writer) (*Pcapng, error) {
	p := &Pcapng{buf: bufio.NewWriter(w)}
	if err := p.writeHeaders(); err != nil {
		return nil, err
	}
	return p, nil
}

// NewPcapngFile creates or truncates path and writes the pcapng headers.
func NewPcapngFile(path string) (*Pcapng, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	p, err := NewPcapng(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	p.closer = f
	return p, nil
}

func (p *Pcapng) writeHeaders() error {
	shb := make([]byte, 28)
	le := binary.LittleEndian
	le.PutUint32(shb[0:4], pcapngSHBType)
	le.PutUint32(shb[4:8], uint32(len(shb)))
	le.PutUint32(shb[8:12], pcapngBOM)
	le.PutUint16(shb[12:14], pcapngVersion)
	le.PutUint16(shb[14:16], 0)
	le.PutUint64(shb[16:24], ^uint64(0))
	le.PutUint32(shb[24:28], uint32(len(shb)))

	idb := make([]byte, 20)
	le.PutUint32(idb[0:4], pcapngIDBType)
	le.PutUint32(idb[4:8], uint32(len(idb)))
	le.PutUint16(idb[8:10], linkTypeEther)
	le.PutUint16(idb[10:12], 0)
	le.PutUint32(idb[12:16], pcapngSnapLen)
	le.PutUint32(idb[16:20], uint32(len(idb)))

	if _, err := p.buf.Write(shb); err != nil {
		return err
	}
	if _, err := p.buf.Write(idb); err != nil {
		return err
	}
	return p.buf.Flush()
}

// Write wraps one ZEP datagram in synthetic Ethernet/IPv4/UDP headers and
// appends it as an enhanced packet block. The block timestamp comes from the
// ZEP header.
func (p *Pcapng) Write(packet []byte) error {
	ts, ok := zep.Timestamp(packet)
	if !ok {
		return fmt.Errorf("pcapng: ZEP datagram too short (%d bytes)", len(packet))
	}
	frame := EthernetFrame(packet)

	micros := uint64(ts.Unix())*1_000_000 + uint64((ts.Nanosecond()+500)/1000)
	padding := (4 - len(frame)%4) % 4
	total := 32 + len(frame) + padding
	block := make([]byte, total)
	le := binary.LittleEndian
	le.PutUint32(block[0:4], pcapngEPBType)
	le.PutUint32(block[4:8], uint32(total))
	le.PutUint32(block[8:12], 0) // interface ID
	le.PutUint32(block[12:16], uint32(micros>>32))
	le.PutUint32(block[16:20], uint32(micros))
	le.PutUint32(block[20:24], uint32(len(frame)))
	le.PutUint32(block[24:28], uint32(len(frame)))
	copy(block[28:], frame)
	le.PutUint32(block[total-4:], uint32(total))

	if _, err := p.buf.Write(block); err != nil {
		return err
	}
	// Flush every packet so a live capture can be opened while it is still
	// being written.
	return p.buf.Flush()
}

// Close flushes buffered data and closes the file, if this sink owns one.
func (p *Pcapng) Close() error {
	if p.closed {
		return nil
	}
	p.closed = true
	err := p.buf.Flush()
	if p.closer != nil {
		if cerr := p.closer.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

// EthernetFrame returns the synthetic Ethernet/IPv4/UDP packet used for pcapng
// output. UDP checksum 0 is legal for IPv4.
func EthernetFrame(packet []byte) []byte {
	udpLen := 8 + len(packet)
	ipLen := 20 + udpLen
	frame := make([]byte, 14+ipLen)

	copy(frame[0:6], ethDst[:])
	copy(frame[6:12], ethSrc[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)

	ip := frame[14:34]
	ip[0] = 0x45
	ip[1] = 0
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen))
	binary.BigEndian.PutUint16(ip[4:6], 0)
	binary.BigEndian.PutUint16(ip[6:8], 0)
	ip[8] = 64
	ip[9] = 17 // UDP
	copy(ip[12:16], ipSrc.To4())
	copy(ip[16:20], ipDst.To4())
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))

	udp := frame[34:]
	binary.BigEndian.PutUint16(udp[0:2], zepSrcPort)
	binary.BigEndian.PutUint16(udp[2:4], zepPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udp[6:8], 0)
	copy(udp[8:], packet)

	return frame
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(data[0])<<8 | uint32(data[1])
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
