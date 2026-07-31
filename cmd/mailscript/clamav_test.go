package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeClamd starts a TCP listener that speaks just enough of clamd's
// INSTREAM protocol to drive clamAVScanner: it reads the zINSTREAM command,
// reassembles the length-prefixed chunks until the zero-length terminator,
// then hands the reassembled message to handle, which returns the raw reply
// line to write back (NUL-terminated, matching a real zINSTREAM reply).
func fakeClamd(t *testing.T, handle func(message []byte) string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		cmd := make([]byte, len("zINSTREAM\x00"))
		if _, err := io.ReadFull(conn, cmd); err != nil {
			return
		}
		if string(cmd) != "zINSTREAM\x00" {
			return
		}

		var message []byte
		var sizeBuf [4]byte
		for {
			if _, err := io.ReadFull(conn, sizeBuf[:]); err != nil {
				return
			}
			size := binary.BigEndian.Uint32(sizeBuf[:])
			if size == 0 {
				break
			}
			chunk := make([]byte, size)
			if _, err := io.ReadFull(conn, chunk); err != nil {
				return
			}
			message = append(message, chunk...)
		}

		reply := handle(message)
		_, _ = conn.Write([]byte(reply + "\x00"))
	}()

	return listener.Addr().String()
}

func TestClamAVScannerParsesCleanReply(t *testing.T) {
	addr := fakeClamd(t, func([]byte) string { return "stream: OK" })
	scanner := newClamAVScanner(addr, 2*time.Second, 0)

	result, err := scanner.scan(context.Background(), []byte("hello"))
	if err != nil {
		t.Fatalf("scan() error = %v", err)
	}
	if result.VirusFound || result.Status != "OK" {
		t.Fatalf("scan() = %+v, want a clean OK result", result)
	}
}

func TestClamAVScannerParsesInfectedReply(t *testing.T) {
	addr := fakeClamd(t, func([]byte) string { return "stream: Eicar-Test-Signature FOUND" })
	scanner := newClamAVScanner(addr, 2*time.Second, 0)

	result, err := scanner.scan(context.Background(), []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"))
	if err != nil {
		t.Fatalf("scan() error = %v", err)
	}
	if !result.VirusFound || result.Signature != "Eicar-Test-Signature" || result.Status != "FOUND" {
		t.Fatalf("scan() = %+v, want VirusFound with signature Eicar-Test-Signature", result)
	}
}

// Threats: clamd reporting an error (e.g. its own internal size limit, a
// malformed stream) must never be interpreted as "clean" — that would let a
// message clamd never actually scanned sail through the AV gate silently.
func TestClamAVScannerTreatsErrorReplyAsError(t *testing.T) {
	addr := fakeClamd(t, func([]byte) string { return "stream: INSTREAM size limit exceeded. ERROR" })
	scanner := newClamAVScanner(addr, 2*time.Second, 0)

	_, err := scanner.scan(context.Background(), []byte("hello"))
	if err == nil {
		t.Fatal("scan() = nil error for a clamd ERROR reply, want an error")
	}
	if !strings.Contains(err.Error(), "size limit exceeded") {
		t.Fatalf("scan() error = %v, want it to include clamd's error message", err)
	}
}

// Threats: an unrecognized reply — not matching any of clamd's three known
// shapes — must fail closed (an error), not be silently treated as clean.
func TestClamAVScannerRejectsUnrecognizedReply(t *testing.T) {
	addr := fakeClamd(t, func([]byte) string { return "not a clamd reply at all" })
	scanner := newClamAVScanner(addr, 2*time.Second, 0)

	_, err := scanner.scan(context.Background(), []byte("hello"))
	if err == nil {
		t.Fatal("scan() = nil error for an unrecognized reply, want an error")
	}
}

func TestClamAVScannerRejectsOversizedMessageBeforeSending(t *testing.T) {
	var handlerCalled bool
	addr := fakeClamd(t, func([]byte) string {
		handlerCalled = true
		return "stream: OK"
	})
	scanner := newClamAVScanner(addr, 2*time.Second, 10)

	_, err := scanner.scan(context.Background(), []byte("this message is far longer than ten bytes"))
	if err == nil {
		t.Fatal("scan() = nil error for an oversized message, want a client-side rejection")
	}
	if handlerCalled {
		t.Fatal("scan() sent an oversized message to clamd instead of rejecting it locally")
	}
}

func TestClamAVScannerSendsMultiChunkMessages(t *testing.T) {
	// Exercise the chunking path (clamdChunkSize is 8192) with a message
	// spanning multiple chunks, and verify clamd (the fake) reassembles the
	// exact bytes sent.
	large := make([]byte, clamdChunkSize*2+37)
	for i := range large {
		large[i] = byte(i % 251)
	}

	var received []byte
	addr := fakeClamd(t, func(message []byte) string {
		received = message
		return "stream: OK"
	})
	scanner := newClamAVScanner(addr, 2*time.Second, 0)

	if _, err := scanner.scan(context.Background(), large); err != nil {
		t.Fatalf("scan() error = %v", err)
	}
	if len(received) != len(large) {
		t.Fatalf("clamd received %d bytes, want %d", len(received), len(large))
	}
	for i := range large {
		if received[i] != large[i] {
			t.Fatalf("byte %d corrupted in transit: got %d, want %d", i, received[i], large[i])
		}
	}
}

func TestClamAVScannerFailsClosedWhenUnreachable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close() // nothing is listening now

	scanner := newClamAVScanner(addr, 500*time.Millisecond, 0)
	_, err = scanner.scan(context.Background(), []byte("hello"))
	if err == nil {
		t.Fatal("scan() = nil error against an unreachable clamd, want an error")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) && !strings.Contains(err.Error(), "dial") {
		t.Fatalf("scan() error = %v, want a dial/network error", err)
	}
}
