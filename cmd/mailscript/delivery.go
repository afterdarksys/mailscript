package main

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

type deliveryDisposition struct {
	code       int
	reason     string
	quarantine bool
}

// Policies accumulate actions. An accept cannot override a blocking action.
func policyDisposition(actions []string, forwardQuarantine bool) deliveryDisposition {
	result := deliveryDisposition{code: 250, reason: "Message accepted"}
	for _, action := range actions {
		switch {
		case action == "reject", action == "bounce", action == "drop", action == "discard":
			reason := "Message rejected by " + action + " action"
			if action == "drop" {
				reason = "Message dropped"
			}
			return deliveryDisposition{code: 550, reason: reason}
		case action == "defer":
			return deliveryDisposition{code: 451, reason: "Message deferred by policy"}
		case strings.HasPrefix(action, "smtp_error:"):
			parts := strings.SplitN(action, ":", 3)
			code, err := strconv.Atoi(parts[1])
			if err != nil || code < 400 || code > 599 {
				return deliveryDisposition{code: 451, reason: "Invalid policy SMTP response"}
			}
			reason := "Message blocked by policy"
			if len(parts) == 3 {
				reason = smtpReplyText(parts[2])
			}
			return deliveryDisposition{code: code, reason: reason}
		case action == "quarantine", action == "fileinto:Spam":
			if !forwardQuarantine {
				return deliveryDisposition{code: 550, reason: "Message quarantined by policy"}
			}
			result.quarantine = true
		}
	}
	return result
}

// Host-specific actions cannot be silently ignored when this process owns delivery.
func unsupportedDeliveryAction(actions []string) string {
	for _, action := range actions {
		for _, prefix := range []string{"fileinto:", "auto_reply:", "force_second_pass:", "reply_with_smtp_dsn:", "set_dlp:", "skip_dlp:", "skip_malware_check:", "skip_spam_check:", "skip_whitelist_check:", "set_filter_rules:"} {
			if strings.HasPrefix(action, prefix) && action != "fileinto:Spam" {
				return strings.TrimSuffix(prefix, ":")
			}
		}
		if action == "add_to_digest" {
			return action
		}
	}
	return ""
}

func smtpReplyText(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "\x00", "")), " ")
}

func validEnvelopeAddress(address string, allowEmpty bool) bool {
	if address == "" {
		return allowEmpty
	}
	// Envelope values are interpolated into SMTP commands. Reject command
	// delimiters even for callers that bypass the SMTP parser (e.g. gRPC).
	if strings.ContainsAny(address, "<>\r\n\x00") {
		return false
	}
	for _, r := range address {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

func validateEnvelope(from string, to []string) error {
	if !validEnvelopeAddress(from, true) {
		return fmt.Errorf("invalid envelope sender")
	}
	if len(to) == 0 {
		return fmt.Errorf("at least one envelope recipient is required")
	}
	for _, rcpt := range to {
		if !validEnvelopeAddress(rcpt, false) {
			return fmt.Errorf("invalid envelope recipient")
		}
	}
	return nil
}

func parseSMTPPath(line, prefix string, allowEmpty bool) (string, error) {
	if !strings.HasPrefix(strings.ToUpper(line), prefix) {
		return "", fmt.Errorf("invalid command")
	}
	path := strings.TrimSpace(line[len(prefix):])
	if !strings.HasPrefix(path, "<") {
		return "", fmt.Errorf("missing path")
	}
	end := strings.IndexByte(path, '>')
	if end < 1 {
		return "", fmt.Errorf("unterminated path")
	}
	address := path[1:end]
	if !validEnvelopeAddress(address, allowEmpty) {
		return "", fmt.Errorf("invalid address")
	}
	// Only the extensions advertised by EHLO are supported.
	for _, parameter := range strings.Fields(path[end+1:]) {
		p := strings.ToUpper(parameter)
		if prefix == "MAIL FROM:" && strings.HasPrefix(p, "SIZE=") {
			size, err := strconv.ParseUint(p[5:], 10, 64)
			if err == nil && size <= 50*1024*1024 {
				continue
			}
		}
		if prefix == "MAIL FROM:" && (p == "BODY=8BITMIME" || p == "BODY=7BIT") {
			continue
		}
		return "", fmt.Errorf("unsupported parameter")
	}
	return address, nil
}

func readWireLine(reader *bufio.Reader, limit int) (string, error) {
	var line []byte
	for {
		part, err := reader.ReadSlice('\n')
		if len(line)+len(part) > limit {
			return "", fmt.Errorf("SMTP line too long")
		}
		line = append(line, part...)
		if err == bufio.ErrBufferFull {
			continue
		}
		return string(line), err
	}
}

// RFC message bytes must not gain a different SMTP framing interpretation when
// passed between MTAs. Offline parsing remains tolerant; delivery is strict.
func validateWireData(raw []byte) error {
	if len(raw) > 50*1024*1024 {
		return fmt.Errorf("message exceeds 50 MiB")
	}
	for i, b := range raw {
		if b == '\n' && (i == 0 || raw[i-1] != '\r') {
			return fmt.Errorf("DATA requires CRLF line endings")
		}
		if b == '\r' && (i+1 == len(raw) || raw[i+1] != '\n') {
			return fmt.Errorf("DATA contains a bare carriage return")
		}
	}
	return nil
}
