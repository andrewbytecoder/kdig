package netcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type CaptureStats struct {
	Format       string
	Packets      int
	PayloadBytes int64
}

func ParseCapture(reader io.Reader) (CaptureStats, error) {
	magic := make([]byte, 4)
	if _, err := io.ReadFull(reader, magic); err != nil {
		return CaptureStats{}, fmt.Errorf("read capture magic: %w", err)
	}
	if isPCAPNG(magic) {
		return parsePCAPNG(reader, magic)
	}
	return parsePCAP(reader, magic)
}

func parsePCAP(reader io.Reader, magic []byte) (CaptureStats, error) {
	var order binary.ByteOrder
	switch {
	case matches(magic, 0xd4, 0xc3, 0xb2, 0xa1), matches(magic, 0x4d, 0x3c, 0xb2, 0xa1):
		order = binary.LittleEndian
	case matches(magic, 0xa1, 0xb2, 0xc3, 0xd4), matches(magic, 0xa1, 0xb2, 0x3c, 0x4d):
		order = binary.BigEndian
	default:
		return CaptureStats{}, fmt.Errorf("unknown capture magic %x", magic)
	}
	globalHeader := make([]byte, 20)
	if _, err := io.ReadFull(reader, globalHeader); err != nil {
		return CaptureStats{}, fmt.Errorf("pcap header is truncated: %w", err)
	}

	stats := CaptureStats{Format: "pcap"}
	packetHeader := make([]byte, 16)
	for {
		_, err := io.ReadFull(reader, packetHeader)
		if errors.Is(err, io.EOF) {
			return stats, nil
		}
		if err != nil {
			return stats, fmt.Errorf("pcap packet header is truncated: %w", err)
		}
		capturedLength := int64(order.Uint32(packetHeader[8:12]))
		if _, err := io.CopyN(io.Discard, reader, capturedLength); err != nil {
			return stats, fmt.Errorf("pcap packet data is truncated: %w", err)
		}
		stats.Packets++
		stats.PayloadBytes += capturedLength
	}
}

func parsePCAPNG(reader io.Reader, magic []byte) (CaptureStats, error) {
	stats := CaptureStats{Format: "pcapng"}
	var order binary.ByteOrder
	blockHeader := make([]byte, 8)
	copy(blockHeader[:4], magic)
	if _, err := io.ReadFull(reader, blockHeader[4:8]); err != nil {
		return stats, fmt.Errorf("pcapng section header is truncated: %w", err)
	}

	for {
		if isPCAPNG(blockHeader[:4]) {
			byteOrderMagic := make([]byte, 4)
			if _, err := io.ReadFull(reader, byteOrderMagic); err != nil {
				return stats, fmt.Errorf("pcapng byte-order magic is truncated: %w", err)
			}
			switch {
			case matches(byteOrderMagic, 0x4d, 0x3c, 0x2b, 0x1a):
				order = binary.LittleEndian
			case matches(byteOrderMagic, 0x1a, 0x2b, 0x3c, 0x4d):
				order = binary.BigEndian
			default:
				return stats, fmt.Errorf("pcapng has an invalid byte-order magic")
			}
			blockLength := int64(order.Uint32(blockHeader[4:8]))
			if err := consumeBlockRemainder(reader, order, blockLength, 12); err != nil {
				return stats, fmt.Errorf("invalid pcapng section header: %w", err)
			}
		} else {
			if order == nil {
				return stats, fmt.Errorf("pcapng packet data appeared before a section header")
			}
			blockType := order.Uint32(blockHeader[:4])
			blockLength := int64(order.Uint32(blockHeader[4:8]))
			payloadBytes, packet, err := consumePCAPNGBlock(reader, order, blockType, blockLength)
			if err != nil {
				return stats, err
			}
			if packet {
				stats.Packets++
				stats.PayloadBytes += payloadBytes
			}
		}

		_, err := io.ReadFull(reader, blockHeader)
		if errors.Is(err, io.EOF) {
			return stats, nil
		}
		if err != nil {
			return stats, fmt.Errorf("pcapng block header is truncated: %w", err)
		}
	}
}

func consumePCAPNGBlock(reader io.Reader, order binary.ByteOrder, blockType uint32, blockLength int64) (int64, bool, error) {
	if blockLength < 12 || blockLength%4 != 0 {
		return 0, false, fmt.Errorf("pcapng block length %d is invalid", blockLength)
	}
	var fixedLength int64
	var capturedLength int64
	packet := false
	switch blockType {
	case 0x00000006:
		fixedLength = 20
		packet = true
	case 0x00000003:
		fixedLength = 4
		packet = true
	case 0x00000002:
		fixedLength = 20
		packet = true
	}
	if !packet {
		return 0, false, consumeBlockRemainder(reader, order, blockLength, 8)
	}
	if blockLength < 8+fixedLength+4 {
		return 0, false, fmt.Errorf("pcapng packet block length %d is too small", blockLength)
	}
	fixed := make([]byte, fixedLength)
	if _, err := io.ReadFull(reader, fixed); err != nil {
		return 0, false, fmt.Errorf("pcapng packet block is truncated: %w", err)
	}
	if blockType == 0x00000003 {
		originalLength := int64(order.Uint32(fixed[:4]))
		capturedLength = min(originalLength, blockLength-16)
	} else {
		capturedLength = int64(order.Uint32(fixed[12:16]))
	}
	if capturedLength < 0 || capturedLength > blockLength-8-fixedLength-4 {
		return 0, false, fmt.Errorf("pcapng captured length %d exceeds block length %d", capturedLength, blockLength)
	}
	if err := consumeBlockRemainder(reader, order, blockLength, 8+fixedLength); err != nil {
		return 0, false, err
	}
	return capturedLength, true, nil
}

func consumeBlockRemainder(reader io.Reader, order binary.ByteOrder, blockLength int64, consumed int64) error {
	if blockLength < consumed+4 || blockLength%4 != 0 {
		return fmt.Errorf("pcapng block length %d is invalid", blockLength)
	}
	if _, err := io.CopyN(io.Discard, reader, blockLength-consumed-4); err != nil {
		return fmt.Errorf("pcapng block is truncated: %w", err)
	}
	trailer := make([]byte, 4)
	if _, err := io.ReadFull(reader, trailer); err != nil {
		return fmt.Errorf("pcapng block trailer is truncated: %w", err)
	}
	if int64(order.Uint32(trailer)) != blockLength {
		return fmt.Errorf("pcapng block length mismatch")
	}
	return nil
}

func isPCAPNG(magic []byte) bool {
	return matches(magic, 0x0a, 0x0d, 0x0d, 0x0a)
}

func matches(value []byte, expected ...byte) bool {
	return bytes.Equal(value, expected)
}
