package rules

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"time"

	"github.com/afterdarksys/mailscript/pkg/authverify"
)

// Header is a single header occurrence. Unlike a map, the header list
// preserves both ordering and duplicates, which several validation checks
// (duplicate From, Received chain ordering) depend on.
type Header struct {
	Name     string // name exactly as it appeared on the wire
	Value    string // unfolded value with surrounding whitespace trimmed
	Raw      string // original bytes of the field, including any folded lines
	LineNum  int    // 1-based position within the header block
	Folded   bool   // whether the field spanned more than one line
	MaxOctet int    // length in octets of the longest physical line
}

// Attachment describes one non-inline MIME part.
type Attachment struct {
	Filename    string
	ContentType string
	Disposition string
	Size        int64
	SHA256      string
	IsInline    bool
}

// ReceivedHop is a parsed Received: trace field. Index 0 is the topmost
// (most recent) hop, matching the order the fields appear in the message.
type ReceivedHop struct {
	Index        int
	From         string
	FromIP       string
	By           string
	With         string
	ID           string
	For          string
	Timestamp    time.Time
	HasTimestamp bool
	Raw          string
}

// MessageContext holds the email headers, body and metadata accessible to
// Starlark rules. Fields are populated by ParseMessage or by callers that
// already have the message in a structured form.
type MessageContext struct {
	// Headers maps a canonical header name to its first value. It is kept
	// for compatibility; prefer HeaderList and the Get* accessors, which are
	// case-insensitive and duplicate-aware.
	Headers         map[string]string
	HeaderList      []Header
	Body            string  // raw body as received (undecoded)
	MimeType        string  // top-level Content-Type value
	SpamScore       float64 // externally supplied spam score (0.0 to 10.0)
	VirusStatus     string  // virus scan status: "clean", "infected", "unknown"
	AVSignature     string  // scanner signature when VirusStatus is infected
	AVAvailable     bool    // whether an AV scanner was configured and responded
	SenderDID       string
	Actions         []string          // actions taken by the script, in order
	ModifiedHeaders map[string]string // headers added or modified by the script
	BodySize        int64             // size of the body in bytes
	HeaderSize      int64             // size of the header block in bytes
	EnvelopeSenders []string          // SMTP envelope senders

	ContentFilter      string
	ContentFilterName  string
	ContentFilterRules map[string]string
	Instance           string
	InstanceName       string
	LogEntries         []string

	// Envelope information, when the transport supplies it.
	EnvelopeFrom string
	EnvelopeTo   []string
	// HELO is the name the connecting client announced. SPF needs it when
	// the envelope sender is null.
	HELO string

	// RawHeaderBlock is the header block exactly as received. DKIM
	// canonicalisation operates on these bytes, so verification is only
	// possible when the original form was preserved.
	RawHeaderBlock []byte
	// RawBody is the body exactly as received, before any MIME decoding.
	RawBody []byte

	// TrustedAuthServs lists the authserv-id values this deployment writes
	// itself. An Authentication-Results header bearing any other id is
	// recorded but never treated as a verdict, because the sender can forge
	// one freely.
	TrustedAuthServs []string

	// Verified holds authentication results this process computed from the
	// message bytes and DNS. It is nil when verification was not run.
	Verified *authverify.Result

	// DNS and network information.
	SenderDomain    string
	SenderIP        string
	DNSResolved     bool
	MXRecords       []string
	RBLListed       bool
	RBLName         string
	ReceivedHeaders []string

	// Decoded MIME content.
	TextBody    string
	HTMLBody    string
	Attachments []Attachment
	Parts       []MIMEPart

	// Cumulative rule score and the reasons that contributed to it.
	Score        float64
	ScoreReasons []string

	// Now is the reference time for date-skew checks. Zero means time.Now().
	Now time.Time

	// Resolver performs DNS and RBL lookups. Nil disables network checks and
	// makes the corresponding builtins fall back to the static fields above.
	Resolver *Resolver

	// Lists provides named allow/deny lists to the in_list builtin.
	Lists map[string]map[string]bool

	// headerIndex maps a lowercased header name to indices into HeaderList.
	headerIndex map[string][]int

	// receivedHops caches the parsed Received chain.
	receivedHops []ReceivedHop
	hopsParsed   bool

	// urls caches extracted URLs.
	urls       []string
	urlsParsed bool

	// authResults caches parsed authentication results.
	auth       *AuthResults
	authParsed bool
}

// MIMEPart is a flattened view of one part of the MIME tree.
type MIMEPart struct {
	ContentType string
	Charset     string
	Disposition string
	Filename    string
	Size        int64
	Depth       int
	Content     string // decoded content, populated for text/* parts only
}

// NewMessageContext returns a context with all maps and slices initialised.
func NewMessageContext() *MessageContext {
	return &MessageContext{
		Headers:            make(map[string]string),
		HeaderList:         []Header{},
		ModifiedHeaders:    make(map[string]string),
		ContentFilterRules: make(map[string]string),
		Actions:            []string{},
		LogEntries:         []string{},
		ScoreReasons:       []string{},
		headerIndex:        make(map[string][]int),
		VirusStatus:        "unknown",
	}
}

// reindex rebuilds the case-insensitive header index and the compatibility
// map. It must be called after HeaderList is populated or mutated directly.
func (m *MessageContext) reindex() {
	m.headerIndex = make(map[string][]int, len(m.HeaderList))
	if m.Headers == nil {
		m.Headers = make(map[string]string, len(m.HeaderList))
	}
	for i, h := range m.HeaderList {
		key := strings.ToLower(h.Name)
		m.headerIndex[key] = append(m.headerIndex[key], i)
		canonical := canonicalHeaderName(h.Name)
		if _, exists := m.Headers[canonical]; !exists {
			m.Headers[canonical] = h.Value
		}
	}
	m.ReceivedHeaders = m.GetAll("Received")
}

// SetHeaders replaces the header list and refreshes derived state.
func (m *MessageContext) SetHeaders(headers []Header) {
	m.HeaderList = headers
	m.Headers = make(map[string]string, len(headers))
	m.reindex()
}

// AddHeaderLine appends a header occurrence and refreshes the index.
func (m *MessageContext) AddHeaderLine(name, value string) {
	m.HeaderList = append(m.HeaderList, Header{
		Name:    name,
		Value:   value,
		Raw:     name + ": " + value,
		LineNum: len(m.HeaderList) + 1,
	})
	m.reindex()
}

// Get returns the first value of the named header, matched case-insensitively.
// It falls back to the compatibility map so contexts built by older callers
// that only populate Headers keep working.
func (m *MessageContext) Get(name string) string {
	if idx, ok := m.headerIndex[strings.ToLower(name)]; ok && len(idx) > 0 {
		return m.HeaderList[idx[0]].Value
	}
	// Fall back to a case-insensitive scan of the compatibility map.
	for k, v := range m.Headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// GetAll returns every value of the named header, in the order received.
func (m *MessageContext) GetAll(name string) []string {
	key := strings.ToLower(name)
	if idx, ok := m.headerIndex[key]; ok {
		out := make([]string, 0, len(idx))
		for _, i := range idx {
			out = append(out, m.HeaderList[i].Value)
		}
		return out
	}
	if v := m.Get(name); v != "" {
		return []string{v}
	}
	return nil
}

// Count returns how many times the named header occurs.
func (m *MessageContext) Count(name string) int {
	if idx, ok := m.headerIndex[strings.ToLower(name)]; ok {
		return len(idx)
	}
	if m.Get(name) != "" {
		return 1
	}
	return 0
}

// Has reports whether the named header is present at least once.
func (m *MessageContext) Has(name string) bool {
	return m.Count(name) > 0
}

// RefTime returns the reference time used for skew calculations.
func (m *MessageContext) RefTime() time.Time {
	if m.Now.IsZero() {
		return time.Now()
	}
	return m.Now
}

// AddScore records a scoring contribution with its reason.
func (m *MessageContext) AddScore(points float64, reason string) {
	m.Score += points
	m.ScoreReasons = append(m.ScoreReasons, fmt.Sprintf("%+.1f %s", points, reason))
}

// canonicalHeaderName converts a header name to Its-Canonical-Form.
func canonicalHeaderName(name string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(name)), "-")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "-")
}

// SplitMessage separates the header block from the body. The returned header
// block excludes the blank separator line. If no separator is found the whole
// input is treated as headers, matching how a truncated message is handled by
// most MTAs.
func SplitMessage(raw []byte) (headerBlock, body []byte) {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return raw[:i], raw[i+4:]
	}
	if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		return raw[:i], raw[i+2:]
	}
	return raw, nil
}

// ParseHeaderBlock parses a raw header block into ordered Header records,
// unfolding continuation lines while retaining the original bytes so that
// validation can inspect line lengths and non-ASCII octets.
func ParseHeaderBlock(block []byte) []Header {
	lines := splitLines(block)
	var headers []Header
	var cur *Header

	flush := func() {
		if cur != nil {
			cur.Value = strings.TrimSpace(cur.Value)
			headers = append(headers, *cur)
			cur = nil
		}
	}

	for _, line := range lines {
		trimmedRight := strings.TrimRight(line, "\r\n")
		octets := len(trimmedRight)

		if cur != nil && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
			// Continuation of the previous field (RFC 5322 folding).
			//
			// Raw must rejoin with CRLF, not LF. DKIM simple header
			// canonicalisation re-emits the field byte for byte, so a bare LF
			// here yields a different octet sequence than the signer hashed
			// and every simple-canonicalised signature fails. The
			// DKIM-Signature field is itself always folded, so that would be
			// every such message, not an edge case.
			cur.Value += " " + strings.TrimSpace(trimmedRight)
			cur.Raw += "\r\n" + trimmedRight
			cur.Folded = true
			if octets > cur.MaxOctet {
				cur.MaxOctet = octets
			}
			continue
		}

		flush()

		if trimmedRight == "" {
			continue
		}

		idx := strings.Index(trimmedRight, ":")
		if idx <= 0 {
			// A line with no colon is not a valid field. Record it so that
			// validation can flag it rather than silently dropping it.
			cur = &Header{
				Name:     "",
				Value:    trimmedRight,
				Raw:      trimmedRight,
				LineNum:  len(headers) + 1,
				MaxOctet: octets,
			}
			continue
		}

		cur = &Header{
			Name:     trimmedRight[:idx],
			Value:    trimmedRight[idx+1:],
			Raw:      trimmedRight,
			LineNum:  len(headers) + 1,
			MaxOctet: octets,
		}
	}
	flush()

	return headers
}

func splitLines(b []byte) []string {
	s := string(b)
	if s == "" {
		return nil
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	// Split leaves a trailing empty element when the block ends with a newline.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// ParseMessage builds a fully populated MessageContext from a raw RFC 5322
// message, including a decoded MIME body and attachment inventory. A parse
// failure in the MIME tree is not fatal: headers and the raw body are still
// returned so that rules can act on a malformed message.
func ParseMessage(raw []byte) (*MessageContext, error) {
	ctx := NewMessageContext()

	headerBlock, body := SplitMessage(raw)
	ctx.SetHeaders(ParseHeaderBlock(headerBlock))

	// Retain the original bytes: DKIM canonicalisation operates on them, and
	// any normalisation would invalidate an otherwise good signature.
	ctx.RawHeaderBlock = headerBlock
	ctx.RawBody = body

	ctx.Body = string(body)
	ctx.BodySize = int64(len(body))
	ctx.HeaderSize = int64(len(headerBlock))
	ctx.MimeType = ctx.Get("Content-Type")
	ctx.SenderDomain = DomainOf(ctx.Get("From"))

	ctx.decodeMIME()

	return ctx, nil
}

// decodeMIME walks the MIME tree, collecting decoded text parts and an
// attachment inventory. Errors are tolerated; whatever was decoded before the
// error is retained.
func (m *MessageContext) decodeMIME() {
	ctype := m.Get("Content-Type")
	if ctype == "" {
		// No Content-Type: treat the whole body as text/plain per RFC 2045.
		m.TextBody = m.Body
		m.Parts = []MIMEPart{{
			ContentType: "text/plain",
			Size:        int64(len(m.Body)),
			Content:     m.Body,
		}}
		return
	}

	mediaType, params, err := mime.ParseMediaType(ctype)
	if err != nil {
		m.TextBody = m.Body
		return
	}

	if !strings.HasPrefix(mediaType, "multipart/") {
		decoded := decodeBody([]byte(m.Body), m.Get("Content-Transfer-Encoding"))
		part := MIMEPart{
			ContentType: mediaType,
			Charset:     params["charset"],
			Size:        int64(len(decoded)),
		}
		if strings.HasPrefix(mediaType, "text/") {
			part.Content = string(decoded)
			m.assignTextPart(mediaType, string(decoded))
		}
		m.Parts = append(m.Parts, part)
		return
	}

	boundary := params["boundary"]
	if boundary == "" {
		m.TextBody = m.Body
		return
	}

	m.walkMultipart([]byte(m.Body), boundary, 0)
}

const maxMIMEDepth = 12

func (m *MessageContext) walkMultipart(body []byte, boundary string, depth int) {
	if depth > maxMIMEDepth {
		return
	}

	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		part, err := reader.NextPart()
		if err != nil {
			return // io.EOF or a malformed part; keep what we have
		}

		partBody, readErr := io.ReadAll(part)
		part.Close()
		if readErr != nil && len(partBody) == 0 {
			continue
		}

		ctype := part.Header.Get("Content-Type")
		mediaType, params, err := mime.ParseMediaType(ctype)
		if err != nil {
			mediaType = "text/plain"
			params = map[string]string{}
		}

		if strings.HasPrefix(mediaType, "multipart/") {
			if nested := params["boundary"]; nested != "" {
				m.walkMultipart(partBody, nested, depth+1)
			}
			continue
		}

		decoded := decodeBody(partBody, part.Header.Get("Content-Transfer-Encoding"))
		disposition, dispParams, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		filename := dispParams["filename"]
		if filename == "" {
			filename = params["name"]
		}
		filename = decodeWord(filename)

		mp := MIMEPart{
			ContentType: mediaType,
			Charset:     params["charset"],
			Disposition: disposition,
			Filename:    filename,
			Size:        int64(len(decoded)),
			Depth:       depth,
		}

		if strings.HasPrefix(mediaType, "text/") && disposition != "attachment" {
			mp.Content = string(decoded)
			m.assignTextPart(mediaType, string(decoded))
		}
		m.Parts = append(m.Parts, mp)

		if disposition == "attachment" || filename != "" {
			sum := sha256.Sum256(decoded)
			m.Attachments = append(m.Attachments, Attachment{
				Filename:    filename,
				ContentType: mediaType,
				Disposition: disposition,
				Size:        int64(len(decoded)),
				SHA256:      hex.EncodeToString(sum[:]),
				IsInline:    disposition == "inline",
			})
		}
	}
}

func (m *MessageContext) assignTextPart(mediaType, content string) {
	switch mediaType {
	case "text/plain":
		if m.TextBody == "" {
			m.TextBody = content
		}
	case "text/html":
		if m.HTMLBody == "" {
			m.HTMLBody = content
		}
	}
}

// decodeBody applies the transfer encoding named in the header. Unknown or
// absent encodings return the input unchanged.
func decodeBody(data []byte, encoding string) []byte {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		clean := bytes.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, data)
		decoded, err := base64.StdEncoding.DecodeString(string(clean))
		if err != nil {
			// Tolerate truncated base64 by decoding the longest valid prefix.
			n := (len(clean) / 4) * 4
			if n > 0 {
				if partial, perr := base64.StdEncoding.DecodeString(string(clean[:n])); perr == nil {
					return partial
				}
			}
			return data
		}
		return decoded
	case "quoted-printable":
		decoded, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(data)))
		if err != nil && len(decoded) == 0 {
			return data
		}
		return decoded
	default:
		return data
	}
}

var wordDecoder = &mime.WordDecoder{
	CharsetReader: func(charset string, input io.Reader) (io.Reader, error) {
		// Unsupported charsets are passed through as raw bytes rather than
		// failing the decode; filtering on mojibake beats filtering on nothing.
		return input, nil
	},
}

// decodeWord decodes RFC 2047 encoded-words, returning the input unchanged if
// it is not encoded or cannot be decoded.
func decodeWord(s string) string {
	if s == "" || !strings.Contains(s, "=?") {
		return s
	}
	decoded, err := wordDecoder.DecodeHeader(s)
	if err != nil {
		return s
	}
	return decoded
}

// Address is a parsed mailbox.
type Address struct {
	Name    string
	Address string
	Local   string
	Domain  string
	Valid   bool
}

// ParseAddress parses a single mailbox specification. Invalid input still
// yields a best-effort result with Valid set to false, because rules
// frequently need to reason about malformed addresses.
func ParseAddress(s string) Address {
	s = strings.TrimSpace(s)
	if s == "" {
		return Address{}
	}

	if parsed, err := mail.ParseAddress(s); err == nil {
		local, domain := splitAddress(parsed.Address)
		return Address{
			Name:    decodeWord(parsed.Name),
			Address: parsed.Address,
			Local:   local,
			Domain:  domain,
			Valid:   true,
		}
	}

	// Best effort: pull the angle-addr or the bare token out of the field.
	raw := s
	if i := strings.LastIndex(s, "<"); i >= 0 {
		if j := strings.Index(s[i:], ">"); j > 0 {
			raw = s[i+1 : i+j]
		}
	}
	raw = strings.Trim(strings.TrimSpace(raw), "\"'")
	local, domain := splitAddress(raw)
	name := ""
	if i := strings.LastIndex(s, "<"); i > 0 {
		name = strings.Trim(strings.TrimSpace(s[:i]), "\"")
	}
	return Address{
		Name:    decodeWord(name),
		Address: raw,
		Local:   local,
		Domain:  domain,
		Valid:   false,
	}
}

// ParseAddressList parses a comma-separated address field.
func ParseAddressList(s string) []Address {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	if parsed, err := mail.ParseAddressList(s); err == nil {
		out := make([]Address, 0, len(parsed))
		for _, a := range parsed {
			local, domain := splitAddress(a.Address)
			out = append(out, Address{
				Name:    decodeWord(a.Name),
				Address: a.Address,
				Local:   local,
				Domain:  domain,
				Valid:   true,
			})
		}
		return out
	}
	// Fall back to a naive split so a single malformed mailbox does not hide
	// the rest of the list from the rules.
	var out []Address
	for _, chunk := range splitAddressList(s) {
		if strings.TrimSpace(chunk) == "" {
			continue
		}
		out = append(out, ParseAddress(chunk))
	}
	return out
}

// splitAddressList splits on commas that are not inside quotes or angle
// brackets, which a plain strings.Split would get wrong for display names
// such as "Doe, Jane" <jane@example.com>.
func splitAddressList(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote, inAngle := false, false
	for _, r := range s {
		switch r {
		case '"':
			inQuote = !inQuote
		case '<':
			if !inQuote {
				inAngle = true
			}
		case '>':
			if !inQuote {
				inAngle = false
			}
		case ',':
			if !inQuote && !inAngle {
				out = append(out, cur.String())
				cur.Reset()
				continue
			}
		}
		cur.WriteRune(r)
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, cur.String())
	}
	return out
}

func splitAddress(addr string) (local, domain string) {
	i := strings.LastIndex(addr, "@")
	if i < 0 {
		return addr, ""
	}
	return addr[:i], strings.ToLower(addr[i+1:])
}

// DomainOf extracts the lowercased domain from an address or address field.
func DomainOf(s string) string {
	return ParseAddress(s).Domain
}
