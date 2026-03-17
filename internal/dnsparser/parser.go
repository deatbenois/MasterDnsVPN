package dnsparser

import (
	"encoding/binary"
	"errors"
	"strings"
)

var (
	ErrPacketTooShort  = errors.New("dns packet too short")
	ErrInvalidName     = errors.New("invalid dns name")
	ErrInvalidQuestion = errors.New("invalid dns question section")
	ErrInvalidAnswer   = errors.New("invalid dns resource record section")
)

const (
	dnsHeaderSize = 12
	maxNameJumps  = 10
)

type Header struct {
	ID      uint16
	Flags   uint16
	QR      uint8
	OpCode  uint8
	AA      uint8
	TC      uint8
	RD      uint8
	RA      uint8
	Z       uint8
	RCode   uint8
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

type ResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RDLen uint16
	RData []byte
}

type Packet struct {
	Header      Header
	Questions   []Question
	Answers     []ResourceRecord
	Authorities []ResourceRecord
	Additional  []ResourceRecord
}

type LitePacket struct {
	Header        Header
	FirstQuestion Question
	HasQuestion   bool
}

func IsDNSPacket(data []byte) bool {
	_, err := ParsePacketLite(data)
	return err == nil
}

func ParsePacketLite(data []byte) (LitePacket, error) {
	if len(data) < dnsHeaderSize {
		return LitePacket{}, ErrPacketTooShort
	}

	header := parseHeader(data)
	packet := LitePacket{Header: header}
	if header.QDCount == 0 {
		return packet, nil
	}

	name, offset, err := parseName(data, dnsHeaderSize)
	if err != nil {
		return LitePacket{}, ErrInvalidQuestion
	}
	if offset+4 > len(data) {
		return LitePacket{}, ErrInvalidQuestion
	}

	packet.FirstQuestion = Question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(data[offset : offset+2]),
		Class: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
	}
	packet.HasQuestion = true
	return packet, nil
}

func ParsePacket(data []byte) (Packet, error) {
	if len(data) < dnsHeaderSize {
		return Packet{}, ErrPacketTooShort
	}

	header := parseHeader(data)
	offset := dnsHeaderSize

	questions, nextOffset, err := parseQuestions(data, offset, int(header.QDCount))
	if err != nil {
		return Packet{}, err
	}
	offset = nextOffset

	answers, nextOffset, err := parseResourceRecords(data, offset, int(header.ANCount))
	if err != nil {
		return Packet{}, err
	}
	offset = nextOffset

	authorities, nextOffset, err := parseResourceRecords(data, offset, int(header.NSCount))
	if err != nil {
		return Packet{}, err
	}
	offset = nextOffset

	additional, _, err := parseResourceRecords(data, offset, int(header.ARCount))
	if err != nil {
		return Packet{}, err
	}

	return Packet{
		Header:      header,
		Questions:   questions,
		Answers:     answers,
		Authorities: authorities,
		Additional:  additional,
	}, nil
}

func parseHeader(data []byte) Header {
	flags := binary.BigEndian.Uint16(data[2:4])
	return Header{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		Flags:   flags,
		QR:      uint8((flags >> 15) & 0x1),
		OpCode:  uint8((flags >> 11) & 0xF),
		AA:      uint8((flags >> 10) & 0x1),
		TC:      uint8((flags >> 9) & 0x1),
		RD:      uint8((flags >> 8) & 0x1),
		RA:      uint8((flags >> 7) & 0x1),
		Z:       uint8((flags >> 4) & 0x7),
		RCode:   uint8(flags & 0xF),
		QDCount: binary.BigEndian.Uint16(data[4:6]),
		ANCount: binary.BigEndian.Uint16(data[6:8]),
		NSCount: binary.BigEndian.Uint16(data[8:10]),
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}
}

func parseQuestions(data []byte, offset int, count int) ([]Question, int, error) {
	if count == 0 {
		return nil, offset, nil
	}

	questions := make([]Question, 0, count)
	for i := 0; i < count; i++ {
		name, nextOffset, err := parseName(data, offset)
		if err != nil {
			return nil, offset, ErrInvalidQuestion
		}
		offset = nextOffset

		if offset+4 > len(data) {
			return nil, offset, ErrInvalidQuestion
		}

		questions = append(questions, Question{
			Name:  name,
			Type:  binary.BigEndian.Uint16(data[offset : offset+2]),
			Class: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
		})
		offset += 4
	}

	return questions, offset, nil
}

func parseResourceRecords(data []byte, offset int, count int) ([]ResourceRecord, int, error) {
	if count == 0 {
		return nil, offset, nil
	}

	records := make([]ResourceRecord, 0, count)
	for i := 0; i < count; i++ {
		name, nextOffset, err := parseName(data, offset)
		if err != nil {
			return nil, offset, ErrInvalidAnswer
		}
		offset = nextOffset

		if offset+10 > len(data) {
			return nil, offset, ErrInvalidAnswer
		}

		rType := binary.BigEndian.Uint16(data[offset : offset+2])
		rClass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(data[offset+4 : offset+8])
		rdLen := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10

		end := offset + int(rdLen)
		if end > len(data) {
			return nil, offset, ErrInvalidAnswer
		}

		records = append(records, ResourceRecord{
			Name:  name,
			Type:  rType,
			Class: rClass,
			TTL:   ttl,
			RDLen: rdLen,
			RData: data[offset:end],
		})
		offset = end
	}

	return records, offset, nil
}

func parseName(data []byte, offset int) (string, int, error) {
	if offset >= len(data) {
		return "", offset, ErrInvalidName
	}

	var (
		jumped   bool
		jumps    int
		origNext = offset
		parts    []string
	)

	for {
		if offset >= len(data) {
			return "", origNext, ErrInvalidName
		}

		length := int(data[offset])
		if length == 0 {
			offset++
			if !jumped {
				origNext = offset
			}
			break
		}

		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) || jumps >= maxNameJumps {
				return "", origNext, ErrInvalidName
			}
			ptr := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			if ptr >= len(data) {
				return "", origNext, ErrInvalidName
			}
			if !jumped {
				origNext = offset + 2
				jumped = true
			}
			offset = ptr
			jumps++
			continue
		}

		if length > 63 {
			return "", origNext, ErrInvalidName
		}

		offset++
		end := offset + length
		if end > len(data) {
			return "", origNext, ErrInvalidName
		}
		parts = append(parts, string(data[offset:end]))
		offset = end
		if !jumped {
			origNext = offset
		}
	}

	if len(parts) == 0 {
		return ".", origNext, nil
	}
	return strings.Join(parts, "."), origNext, nil
}
