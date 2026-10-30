// Package serialport enumerates and opens the ConBee II serial port.
package serialport

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	// ConBeeVID and ConBeePID identify a ConBee II (CDC-ACM).
	ConBeeVID = "1cf1"
	ConBeePID = "0030"
	// BaudRate is the sniffer firmware's serial speed.
	BaudRate = 38400
)

// Device is one discovered serial port.
type Device struct {
	Path         string `json:"path"`
	VID          string `json:"vid,omitempty"`
	PID          string `json:"pid,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Product      string `json:"product,omitempty"`
	Serial       string `json:"serial,omitempty"`
	ConBee       bool   `json:"conbee"`
}

// String formats a device for the human-readable `zshark list` output.
func (d Device) String() string {
	s := d.Path
	var details []string
	if d.Product != "" {
		details = append(details, d.Product)
	} else if d.ConBee {
		details = append(details, "ConBee II")
	}
	if d.VID != "" && d.PID != "" {
		details = append(details, fmt.Sprintf("(%s:%s)", d.VID, d.PID))
	}
	if d.Serial != "" {
		details = append(details, "serial="+d.Serial)
	}
	if len(details) > 0 {
		s += "  " + strings.Join(details, " ")
	}
	return s
}

// Enumerate lists candidate ConBee serial ports. Linux uses /dev/ttyACM*;
// macOS uses the usbmodem call-in and call-out device nodes. Explicit paths are
// handled by Find and always take precedence over this list.
func Enumerate() ([]Device, error) {
	patterns := candidatePatterns()
	var devices []Device
	seen := make(map[string]bool)
	for _, pattern := range patterns {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		for _, path := range paths {
			if seen[path] {
				continue
			}
			seen[path] = true
			d := Device{Path: path}
			if runtime.GOOS == "linux" {
				d.VID, d.PID, d.Manufacturer, d.Product, d.Serial = linuxUSBInfo(path)
			}
			d.ConBee = isConBee(d.VID, d.PID)
			devices = append(devices, d)
		}
	}
	sortDevices(devices)
	return devices, nil
}

func candidatePatterns() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{"/dev/tty.usbmodem*", "/dev/cu.usbmodem*"}
	default:
		// Linux, and a harmless fallback for other Unix-like hosts.
		return []string{"/dev/ttyACM*"}
	}
}

func sortDevices(devices []Device) {
	sort.Slice(devices, func(i, j int) bool {
		a, b := devices[i], devices[j]
		if a.ConBee != b.ConBee {
			return a.ConBee
		}
		// On macOS both nodes refer to the same device; prefer the call-out
		// node for outbound serial traffic.
		aCU := strings.HasPrefix(a.Path, "/dev/cu.")
		bCU := strings.HasPrefix(b.Path, "/dev/cu.")
		if aCU != bCU {
			return aCU
		}
		return a.Path < b.Path
	})
}

// Preferred returns the device that auto-detection should use.
func Preferred(devices []Device) (Device, bool) {
	if len(devices) == 0 {
		return Device{}, false
	}
	for _, d := range devices {
		if d.ConBee {
			return d, true
		}
	}
	for _, d := range devices {
		if strings.HasPrefix(d.Path, "/dev/cu.") {
			return d, true
		}
	}
	return devices[0], true
}

// Find resolves an explicit port or auto-detects one. An explicit path is
// returned unchanged (and is never rejected here) so the caller can report the
// real open error.
func Find(explicit string) (Device, error) {
	if explicit != "" {
		d := Device{Path: explicit}
		if runtime.GOOS == "linux" {
			d.VID, d.PID, d.Manufacturer, d.Product, d.Serial = linuxUSBInfo(explicit)
		}
		d.ConBee = isConBee(d.VID, d.PID)
		return d, nil
	}
	devices, err := Enumerate()
	if err != nil {
		return Device{}, err
	}
	d, ok := Preferred(devices)
	if !ok {
		return Device{}, fmt.Errorf("no ConBee II serial port found (tried %s)", strings.Join(candidatePatterns(), ", "))
	}
	return d, nil
}

func isConBee(vid, pid string) bool {
	return strings.EqualFold(vid, ConBeeVID) && strings.EqualFold(pid, ConBeePID)
}

func linuxUSBInfo(devPath string) (vid, pid, manufacturer, product, serial string) {
	name := filepath.Base(devPath)
	dir, err := filepath.EvalSymlinks(filepath.Join("/sys/class/tty", name, "device"))
	if err != nil {
		return "", "", "", "", ""
	}
	for {
		vid = readSysFS(filepath.Join(dir, "idVendor"))
		pid = readSysFS(filepath.Join(dir, "idProduct"))
		if vid != "" && pid != "" {
			manufacturer = readSysFS(filepath.Join(dir, "manufacturer"))
			product = readSysFS(filepath.Join(dir, "product"))
			serial = readSysFS(filepath.Join(dir, "serial"))
			return vid, pid, manufacturer, product, serial
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", "", "", "", ""
		}
		dir = parent
	}
}

func readSysFS(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
