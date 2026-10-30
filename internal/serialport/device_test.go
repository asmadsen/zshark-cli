package serialport_test

import (
	"strings"
	"testing"

	"zshark/internal/serialport"
)

func TestPreferredPrefersConBee(t *testing.T) {
	devices := []serialport.Device{
		{Path: "/dev/ttyACM0", VID: "1234", PID: "5678"},
		{Path: "/dev/ttyACM1", VID: "1cf1", PID: "0030", ConBee: true},
	}
	got, ok := serialport.Preferred(devices)
	if !ok {
		t.Fatal("Preferred returned false")
	}
	if got.Path != "/dev/ttyACM1" {
		t.Errorf("preferred = %s, want /dev/ttyACM1", got.Path)
	}
}

func TestPreferredPrefersCallOutOnMac(t *testing.T) {
	devices := []serialport.Device{
		{Path: "/dev/tty.usbmodem123"},
		{Path: "/dev/cu.usbmodem123"},
	}
	got, ok := serialport.Preferred(devices)
	if !ok {
		t.Fatal("Preferred returned false")
	}
	if got.Path != "/dev/cu.usbmodem123" {
		t.Errorf("preferred = %s, want call-out node", got.Path)
	}
}

func TestPreferredEmpty(t *testing.T) {
	if _, ok := serialport.Preferred(nil); ok {
		t.Fatal("Preferred reported a device for an empty list")
	}
}

func TestExplicitPortWins(t *testing.T) {
	got, err := serialport.Find("/custom/port")
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "/custom/port" {
		t.Errorf("path = %s", got.Path)
	}
}

func TestDeviceString(t *testing.T) {
	d := serialport.Device{
		Path:    "/dev/ttyACM0",
		VID:     "1cf1",
		PID:     "0030",
		Product: "ConBee II",
		Serial:  "ABC",
		ConBee:  true,
	}
	s := d.String()
	for _, want := range []string{"/dev/ttyACM0", "ConBee II", "1cf1:0030", "serial=ABC"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, missing %q", s, want)
		}
	}
}
