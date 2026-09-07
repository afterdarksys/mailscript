package main

import (
	"encoding/base64"
	"strings"
)

func (s *SMTPSession) handleAUTH(parts []string) {
	if !s.proxy.submission {
		s.writeLine("502 AUTH unavailable")
		return
	}
	if !s.tlsActive {
		s.writeLine("538 Encryption required")
		return
	}
	if s.helo == "" || s.mailSet || s.authenticated {
		s.writeLine("503 AUTH not allowed in this state")
		return
	}
	if len(parts) < 2 || len(parts) > 3 || !strings.EqualFold(parts[1], "PLAIN") {
		s.writeLine("504 Use AUTH PLAIN")
		return
	}
	encoded := ""
	if len(parts) == 3 {
		encoded = parts[2]
	} else {
		s.writeLine("334 ")
		line, err := readWireLine(s.reader, 4096)
		if err != nil {
			s.conn.Close()
			return
		}
		encoded = strings.TrimSpace(line)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	fields := strings.Split(string(decoded), "\x00")
	if err != nil || len(fields) != 3 || fields[1] == "" || fields[2] == "" || (fields[0] != "" && fields[0] != fields[1]) {
		s.writeLine("501 Invalid AUTH PLAIN credentials")
		return
	}
	s.authUser, s.authPassword, s.authenticated = fields[1], fields[2], true
	u, err := s.connectUpstream()
	if err != nil {
		s.authUser, s.authPassword, s.authenticated = "", "", false
		if ue, ok := err.(*upstreamError); ok && ue.code == 535 {
			s.writeLine("535 Authentication failed")
		} else {
			s.writeLine("454 Authentication temporarily unavailable")
		}
		return
	}
	u.conn.Close()
	s.writeLine("235 Authentication successful")
}
