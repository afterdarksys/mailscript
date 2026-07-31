package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// clamAVScanner speaks clamd's native INSTREAM protocol directly to a clamd
// daemon (e.g. the stock clamav/clamav Docker image) — no HTTP wrapper.
// Keeping the actual virus-scanning parser in that separate process, not
// linked into this one via cgo/libclamav, is the point: a malformed sample
// that trips a parser bug in ClamAV takes down the sidecar, not the SMTP
// server handling live mail.
type clamAVScanner struct {
	addr     string
	timeout  time.Duration
	maxBytes int64
}

type clamAVResponse struct {
	VirusFound bool   `json:"virus_found"`
	Signature  string `json:"signature"`
	Status     string `json:"status"`
}

// clamdChunkSize is the size of each length-prefixed chunk written during
// INSTREAM. clamd has no opinion on chunk size; this just bounds how much of
// the message sits in memory as one write.
const clamdChunkSize = 8192

func newClamAVScanner(addr string, timeout time.Duration, maxBytes int64) *clamAVScanner {
	return &clamAVScanner{addr: addr, timeout: timeout, maxBytes: maxBytes}
}

// scan sends message to clamd via INSTREAM (see the ClamAV clamd protocol:
// https://docs.clamav.net/manual/Usage/Scanning.html#clamd) and parses its
// reply. Threats: a compromised or malicious clamd could return a crafted
// oversized/malformed response — reads are bounded (bufio.Reader with a max
// line length) and any response not matching the three known reply shapes
// (OK / FOUND / ERROR) is a hard error, not treated as clean.
func (s *clamAVScanner) scan(ctx context.Context, message []byte) (clamAVResponse, error) {
	if s.maxBytes > 0 && int64(len(message)) > s.maxBytes {
		return clamAVResponse{}, fmt.Errorf("message exceeds clamav limit of %d bytes", s.maxBytes)
	}

	dialer := net.Dialer{Timeout: s.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return clamAVResponse{}, fmt.Errorf("dial clamd at %s: %w", s.addr, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(s.timeout)); err != nil {
		return clamAVResponse{}, err
	}

	if err := writeInstream(conn, message); err != nil {
		return clamAVResponse{}, fmt.Errorf("send to clamd: %w", err)
	}

	line, err := readClamdReply(conn)
	if err != nil {
		return clamAVResponse{}, fmt.Errorf("read clamd reply: %w", err)
	}

	return parseClamdReply(line)
}

// writeInstream sends the zINSTREAM command followed by message as
// length-prefixed chunks and a final zero-length chunk, per clamd's
// protocol. The 'z' prefix (vs plain INSTREAM) makes clamd's own reply
// NUL-terminated instead of newline-terminated, which is unambiguous even
// if a signature name somehow contained a newline.
func writeInstream(w net.Conn, message []byte) error {
	if _, err := w.Write([]byte("zINSTREAM\x00")); err != nil {
		return err
	}
	var size [4]byte
	for offset := 0; offset < len(message); offset += clamdChunkSize {
		end := offset + clamdChunkSize
		if end > len(message) {
			end = len(message)
		}
		chunk := message[offset:end]
		binary.BigEndian.PutUint32(size[:], uint32(len(chunk)))
		if _, err := w.Write(size[:]); err != nil {
			return err
		}
		if _, err := w.Write(chunk); err != nil {
			return err
		}
	}
	binary.BigEndian.PutUint32(size[:], 0)
	_, err := w.Write(size[:])
	return err
}

// clamdMaxReplyBytes bounds how much of clamd's reply this client will
// buffer. A legitimate reply ("stream: OK", or "stream: <name> FOUND", or
// "stream: <msg> ERROR") is well under a kilobyte; this only exists to stop
// a misbehaving or compromised clamd from forcing unbounded memory growth.
const clamdMaxReplyBytes = 4096

func readClamdReply(r net.Conn) (string, error) {
	reader := bufio.NewReaderSize(r, clamdMaxReplyBytes)
	line, err := reader.ReadString('\x00')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\x00\r\n"), nil
}

// parseClamdReply interprets one of clamd's three INSTREAM reply shapes.
// Anything else is a hard error rather than being treated as clean —
// fail-closed on an unrecognized reply, per this project's security
// posture: a scanner that returns something we don't understand must not
// silently pass mail through as scanned.
func parseClamdReply(line string) (clamAVResponse, error) {
	const prefix = "stream: "
	if !strings.HasPrefix(line, prefix) {
		return clamAVResponse{}, fmt.Errorf("unrecognized clamd reply: %q", line)
	}
	body := strings.TrimSpace(strings.TrimPrefix(line, prefix))

	switch {
	case body == "OK":
		return clamAVResponse{VirusFound: false, Status: "OK"}, nil
	case strings.HasSuffix(body, "FOUND"):
		signature := strings.TrimSpace(strings.TrimSuffix(body, "FOUND"))
		if signature == "" {
			return clamAVResponse{}, fmt.Errorf("clamd FOUND reply had no signature name: %q", line)
		}
		return clamAVResponse{VirusFound: true, Signature: signature, Status: "FOUND"}, nil
	case strings.HasSuffix(body, "ERROR"):
		return clamAVResponse{}, fmt.Errorf("clamd error: %s", strings.TrimSpace(strings.TrimSuffix(body, "ERROR")))
	default:
		return clamAVResponse{}, fmt.Errorf("unrecognized clamd reply: %q", line)
	}
}
