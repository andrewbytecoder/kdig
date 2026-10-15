package netcap

import (
	"bytes"
	"testing"
)

func TestParseCaptureCountsPackets(t *testing.T) {
	stats, err := ParseCapture(bytes.NewReader(testPcap()))
	if err != nil {
		t.Fatalf("ParseCapture() error = %v", err)
	}
	if stats.Format != "pcap" || stats.Packets != 1 || stats.PayloadBytes != 4 {
		t.Fatalf("ParseCapture() = %#v", stats)
	}
}

func TestParseCaptureRejectsTruncatedPacket(t *testing.T) {
	data := append(testPcapHeader(),
		0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x04, 0x00, 0x00, 0x00,
		0x04, 0x00, 0x00, 0x00,
	)
	if _, err := ParseCapture(bytes.NewReader(data)); err == nil {
		t.Fatal("ParseCapture() error = nil, want truncated packet error")
	}
}
