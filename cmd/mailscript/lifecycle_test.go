package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/afterdarksys/mailscript/pkg/rules"
	"google.golang.org/grpc"
)

func TestFailedReloadKeepsWorkingPolicy(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "filter.star")
	os.WriteFile(filename, []byte("def evaluate():\n    reject()\n"), 0600)
	p := &SMTPProxy{scriptName: filename}
	if err := p.reloadPolicy(); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filename, []byte("broken(:"), 0600)
	if err := p.reloadPolicy(); err == nil {
		t.Fatal("invalid reload accepted")
	}
	ctx := &rules.MessageContext{}
	if err := p.executePolicy(ctx); err != nil {
		t.Fatal(err)
	}
	if len(ctx.Actions) != 1 || ctx.Actions[0] != "reject" {
		t.Fatal(ctx.Actions)
	}
}

func TestDrainWaitsForActiveDelivery(t *testing.T) {
	p := &SMTPProxy{}
	p.sessions.Add(1)
	done := make(chan struct{})
	go func() { p.drain(nil, grpc.NewServer(), time.Second); close(done) }()
	select {
	case <-done:
		t.Fatal("did not drain active session")
	case <-time.After(20 * time.Millisecond):
	}
	p.sessions.Done()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("drain did not finish")
	}
}

func TestDrainDeadlineClosesIdleConnections(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	p := &SMTPProxy{active: map[net.Conn]struct{}{server: {}}}
	p.sessions.Add(1)
	p.drain(nil, grpc.NewServer(), 20*time.Millisecond)
	client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle connection left open")
	}
	p.sessions.Done()
}
