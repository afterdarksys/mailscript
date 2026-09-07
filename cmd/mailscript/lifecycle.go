package main

import (
	"net"
	"time"

	"github.com/afterdarksys/mailscript/pkg/rules"
	"google.golang.org/grpc"
)

func (p *SMTPProxy) reloadPolicy() error {
	snapshot, err := rules.LoadPolicy(p.scriptName)
	if err != nil {
		return err
	}
	p.policy.Store(snapshot)
	return nil
}

func (p *SMTPProxy) executePolicy(ctx *rules.MessageContext) error {
	if snapshot := p.policy.Load(); snapshot != nil {
		return snapshot.Execute(ctx, p.engineOptions())
	}
	return rules.ExecuteEngineWithOptions(p.script, ctx, p.engineOptions())
}

func (p *SMTPProxy) drain(listeners []net.Listener, server *grpc.Server, timeout time.Duration) {
	p.connMutex.Lock()
	p.draining = true
	p.connMutex.Unlock()
	for _, listener := range listeners {
		listener.Close()
	}
	done := make(chan struct{})
	go func() { p.sessions.Wait(); close(done) }()
	rpcDone := make(chan struct{})
	go func() { server.GracefulStop(); close(rpcDone) }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for done != nil || rpcDone != nil {
		select {
		case <-done:
			done = nil
		case <-rpcDone:
			rpcDone = nil
		case <-timer.C:
			server.Stop()
			p.connMutex.Lock()
			for conn := range p.active {
				conn.Close()
			}
			p.connMutex.Unlock()
			return
		}
	}
}
