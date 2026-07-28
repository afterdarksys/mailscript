package rules

import (
	"math"
	"mime"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// regexCache memoises compiled patterns. Rule scripts call regex_match in
// loops over every message, and recompiling the same pattern each time
// dominates the cost of an otherwise trivial rule.
//
// Go's regexp is RE2, so a pathological pattern costs linear time rather than
// exponential; the cache is a throughput optimisation, not a DoS control.
var regexCache sync.Map // string -> *cachedRegexp

type cachedRegexp struct {
	re  *regexp.Regexp
	err error
}

// maxCachedPatterns bounds the cache so that a script generating patterns
// dynamically cannot grow it without limit.
const maxCachedPatterns = 4096

var regexCacheSize int64
var regexCacheMu sync.Mutex

// CompileRegex returns a compiled pattern, reusing a cached copy when
// available.
func CompileRegex(pattern string) (*regexp.Regexp, error) {
	if v, ok := regexCache.Load(pattern); ok {
		entry := v.(*cachedRegexp)
		return entry.re, entry.err
	}

	re, err := regexp.Compile(pattern)
	entry := &cachedRegexp{re: re, err: err}

	regexCacheMu.Lock()
	if regexCacheSize < maxCachedPatterns {
		regexCache.Store(pattern, entry)
		regexCacheSize++
	}
	regexCacheMu.Unlock()

	return re, err
}

// MatchRegex reports whether the pattern matches the text. A pattern that
// fails to compile matches nothing and returns the compile error, so a typo
// in a rule fails closed rather than silently matching everything.
func MatchRegex(pattern, text string) (bool, error) {
	re, err := CompileRegex(pattern)
	if err != nil {
		return false, err
	}
	return re.MatchString(text), nil
}

// urlPattern matches absolute URLs and bare hostnames that a mail client
// would linkify.
var urlPattern = regexp.MustCompile(`(?i)\b((?:https?|ftp|mailto)://[^\s<>"'\)\]]+|www\.[a-z0-9-]+(?:\.[a-z0-9-]+)+[^\s<>"'\)\]]*)`)

// hrefPattern captures the href target and the anchor text of an HTML link.
var hrefPattern = regexp.MustCompile(`(?is)<a\s[^>]*href\s*=\s*["']?([^"'\s>]+)["']?[^>]*>(.*?)</a>`)

// imgPattern captures image tags so tracking pixels can be identified.
var imgPattern = regexp.MustCompile(`(?is)<img\s[^>]*>`)

// tagPattern strips HTML tags when converting to text.
var tagPattern = regexp.MustCompile(`(?s)<[^>]*>`)

// URLs returns every URL found in the decoded text and HTML bodies, with
// duplicates removed and order preserved.
func (m *MessageContext) URLs() []string {
	if m.urlsParsed {
		return m.urls
	}

	seen := map[string]bool{}
	var out []string

	collect := func(text string) {
		for _, match := range urlPattern.FindAllString(text, -1) {
			cleaned := strings.TrimRight(match, ".,;:!?")
			if cleaned == "" || seen[cleaned] {
				continue
			}
			seen[cleaned] = true
			out = append(out, cleaned)
		}
	}

	// Prefer href targets from HTML, then sweep the raw text of both parts.
	for _, match := range hrefPattern.FindAllStringSubmatch(m.HTMLBody, -1) {
		href := strings.TrimSpace(match[1])
		if href == "" || strings.HasPrefix(href, "#") || seen[href] {
			continue
		}
		seen[href] = true
		out = append(out, href)
	}
	collect(m.HTMLBody)
	collect(m.TextBody)
	if m.TextBody == "" && m.HTMLBody == "" {
		collect(m.Body)
	}

	m.urls = out
	m.urlsParsed = true
	return out
}

// URLDomains returns the distinct hostnames referenced by the message's URLs.
func (m *MessageContext) URLDomains() []string {
	seen := map[string]bool{}
	var out []string
	for _, raw := range m.URLs() {
		host := hostOfURL(raw)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, host)
	}
	return out
}

func hostOfURL(raw string) string {
	if strings.HasPrefix(strings.ToLower(raw), "mailto:") {
		return DomainOf(raw[len("mailto:"):])
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

// urlShorteners are the hosts most often used to hide a destination from both
// the recipient and a URL-reputation lookup.
var urlShorteners = map[string]bool{
	"bit.ly": true, "tinyurl.com": true, "goo.gl": true, "t.co": true,
	"ow.ly": true, "is.gd": true, "buff.ly": true, "adf.ly": true,
	"bit.do": true, "cutt.ly": true, "rebrand.ly": true, "shorte.st": true,
	"rb.gy": true, "tiny.cc": true, "lnkd.in": true, "db.tt": true,
	"qr.ae": true, "j.mp": true, "soo.gd": true, "s2r.co": true,
	"clicky.me": true, "budurl.com": true, "shorturl.at": true,
}

// HasURLShortener reports whether any link points at a known shortener.
func (m *MessageContext) HasURLShortener() bool {
	for _, host := range m.URLDomains() {
		if urlShorteners[host] || urlShorteners[RegisteredDomain(host)] {
			return true
		}
	}
	return false
}

// URLMismatch describes an HTML link whose visible text names a different
// destination than its href, the mechanic behind most phishing links.
type URLMismatch struct {
	Href        string
	DisplayText string
	HrefHost    string
	DisplayHost string
}

// URLDisplayMismatches returns links whose anchor text advertises a hostname
// that does not match the actual href host. Anchor text that is not itself a
// URL or hostname is ignored, since ordinary link text says nothing about the
// destination.
func (m *MessageContext) URLDisplayMismatches() []URLMismatch {
	var out []URLMismatch

	for _, match := range hrefPattern.FindAllStringSubmatch(m.HTMLBody, -1) {
		href := strings.TrimSpace(match[1])
		text := strings.TrimSpace(stripHTMLTags(match[2]))
		if href == "" || text == "" {
			continue
		}

		displayHost := hostOfURL(text)
		if displayHost == "" || !strings.Contains(displayHost, ".") {
			continue // the anchor text is not claiming a destination
		}
		// Require the text to actually look like a URL or bare host, not a
		// sentence that happens to contain a dot.
		if strings.ContainsAny(text, " \t") && !strings.Contains(text, "://") {
			continue
		}

		hrefHost := hostOfURL(href)
		if hrefHost == "" || SameOrgDomain(hrefHost, displayHost) {
			continue
		}

		out = append(out, URLMismatch{
			Href:        href,
			DisplayText: text,
			HrefHost:    hrefHost,
			DisplayHost: displayHost,
		})
	}

	return out
}

// TrackingPixelCount counts images that are sized to be invisible, the usual
// marker of open-tracking in bulk mail.
func (m *MessageContext) TrackingPixelCount() int {
	count := 0
	for _, tag := range imgPattern.FindAllString(m.HTMLBody, -1) {
		lower := strings.ToLower(tag)
		if hasTinyDimension(lower, "width") && hasTinyDimension(lower, "height") {
			count++
			continue
		}
		if strings.Contains(lower, "display:none") || strings.Contains(lower, "visibility:hidden") {
			count++
		}
	}
	return count
}

var dimensionPattern = regexp.MustCompile(`(?i)(width|height)\s*[:=]\s*["']?\s*(\d+)`)

func hasTinyDimension(tag, attr string) bool {
	for _, match := range dimensionPattern.FindAllStringSubmatch(tag, -1) {
		if !strings.EqualFold(match[1], attr) {
			continue
		}
		if len(match[2]) <= 1 { // 0 through 9 pixels
			return true
		}
	}
	return false
}

// stripHTMLTags renders HTML as approximate plain text.
func stripHTMLTags(html string) string {
	text := tagPattern.ReplaceAllString(html, " ")
	replacer := strings.NewReplacer(
		"&nbsp;", " ", "&amp;", "&", "&lt;", "<", "&gt;", ">",
		"&quot;", "\"", "&#39;", "'", "&apos;", "'",
	)
	text = replacer.Replace(text)
	return strings.Join(strings.Fields(text), " ")
}

// HTMLToText converts the HTML part to plain text for content matching.
func (m *MessageContext) HTMLToText() string {
	return stripHTMLTags(m.HTMLBody)
}

// SearchText returns the text a content rule should search: the plain part
// when present, otherwise the HTML rendered to text, otherwise the raw body.
func (m *MessageContext) SearchText() string {
	if m.TextBody != "" {
		return m.TextBody
	}
	if m.HTMLBody != "" {
		return m.HTMLToText()
	}
	return m.Body
}

// executableExtensions are file types that execute on open, either directly
// or through a scripting host.
var executableExtensions = map[string]bool{
	"exe": true, "scr": true, "com": true, "pif": true, "bat": true,
	"cmd": true, "js": true, "jse": true, "vbs": true, "vbe": true,
	"wsf": true, "wsh": true, "ps1": true, "psm1": true, "hta": true,
	"msi": true, "msp": true, "jar": true, "app": true, "dmg": true,
	"lnk": true, "reg": true, "scf": true, "inf": true, "cpl": true,
	"dll": true, "sys": true, "iso": true, "img": true, "vhd": true,
	"apk": true, "deb": true, "rpm": true, "run": true, "bin": true,
}

// macroExtensions are Office formats that can carry executable macros.
var macroExtensions = map[string]bool{
	"docm": true, "dotm": true, "xlsm": true, "xltm": true, "xlam": true,
	"pptm": true, "potm": true, "ppam": true, "ppsm": true, "sldm": true,
	"doc": true, "xls": true, "ppt": true, "xlsb": true,
}

// archiveExtensions are containers that hide their contents from a scanner
// that does not unpack them.
var archiveExtensions = map[string]bool{
	"zip": true, "rar": true, "7z": true, "tar": true, "gz": true,
	"bz2": true, "xz": true, "cab": true, "ace": true, "arj": true,
	"lzh": true, "z": true, "tgz": true,
}

// FileExtension returns the lowercased final extension of a filename.
func FileExtension(filename string) string {
	i := strings.LastIndex(filename, ".")
	if i < 0 || i == len(filename)-1 {
		return ""
	}
	return strings.ToLower(filename[i+1:])
}

// HasExecutableAttachment reports whether any attachment is a directly
// executable file type.
func (m *MessageContext) HasExecutableAttachment() bool {
	for _, a := range m.Attachments {
		if executableExtensions[FileExtension(a.Filename)] {
			return true
		}
	}
	return false
}

// HasMacroAttachment reports whether any attachment is an Office format that
// can carry macros.
func (m *MessageContext) HasMacroAttachment() bool {
	for _, a := range m.Attachments {
		if macroExtensions[FileExtension(a.Filename)] {
			return true
		}
	}
	return false
}

// HasArchiveAttachment reports whether any attachment is an archive.
func (m *MessageContext) HasArchiveAttachment() bool {
	for _, a := range m.Attachments {
		if archiveExtensions[FileExtension(a.Filename)] {
			return true
		}
	}
	return false
}

// DoubleExtensionAttachments returns attachments whose name carries a
// second, benign-looking extension in front of the real one, as in
// "invoice.pdf.exe".
func (m *MessageContext) DoubleExtensionAttachments() []string {
	var out []string
	for _, a := range m.Attachments {
		parts := strings.Split(strings.ToLower(a.Filename), ".")
		if len(parts) < 3 {
			continue
		}
		final := parts[len(parts)-1]
		penultimate := parts[len(parts)-2]
		if !executableExtensions[final] && !macroExtensions[final] {
			continue
		}
		// The decoy extension must itself look like a document type.
		switch penultimate {
		case "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt",
			"jpg", "jpeg", "png", "gif", "html", "htm", "csv", "rtf", "zip":
			out = append(out, a.Filename)
		}
	}
	return out
}

// RTLOverrideAttachments returns attachments whose filename contains a
// bidirectional override character, used to make "exe.txt" render as
// "txt.exe" reversed so the real extension is hidden.
func (m *MessageContext) RTLOverrideAttachments() []string {
	var out []string
	for _, a := range m.Attachments {
		if strings.ContainsAny(a.Filename, "‪‫‬‭‮⁦⁧⁨⁩") {
			out = append(out, a.Filename)
		}
	}
	return out
}

// Entropy returns the Shannon entropy of a string in bits per byte. Encrypted
// or compressed content approaches 8; ordinary prose sits near 4.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	total := float64(len(s))
	entropy := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// UppercaseRatio returns the fraction of cased letters that are uppercase.
func UppercaseRatio(s string) float64 {
	upper, total := 0, 0
	for _, r := range s {
		if !unicode.IsLetter(r) {
			continue
		}
		total++
		if unicode.IsUpper(r) {
			upper++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(upper) / float64(total)
}

// NonASCIIRatio returns the fraction of runes outside US-ASCII.
func NonASCIIRatio(s string) float64 {
	if s == "" {
		return 0
	}
	total, nonASCII := 0, 0
	for _, r := range s {
		total++
		if r > unicode.MaxASCII {
			nonASCII++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(nonASCII) / float64(total)
}

// HTMLTextRatio returns the ratio of HTML markup bytes to visible text bytes.
// A high ratio indicates markup used to break up text against filters.
func (m *MessageContext) HTMLTextRatio() float64 {
	if m.HTMLBody == "" {
		return 0
	}
	text := m.HTMLToText()
	if len(text) == 0 {
		return math.Inf(1)
	}
	return float64(len(m.HTMLBody)) / float64(len(text))
}

// CountMatches returns the number of non-overlapping matches of a pattern.
func CountMatches(pattern, text string) (int, error) {
	re, err := CompileRegex(pattern)
	if err != nil {
		return 0, err
	}
	return len(re.FindAllString(text, -1)), nil
}

// ipPattern matches IPv4 and bracketed IPv6 literals.
var ipPattern = regexp.MustCompile(`\[?((?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})\]?`)

// bracketedIPPattern matches an IP inside square brackets, the conventional
// way a Received field records the connecting client's address.
var bracketedIPPattern = regexp.MustCompile(`\[(?:IPv6:)?((?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})\]`)

// firstBracketedIP returns the first bracketed IP literal in a string.
func firstBracketedIP(s string) string {
	for _, match := range bracketedIPPattern.FindAllStringSubmatch(s, -1) {
		if net.ParseIP(match[1]) != nil {
			return match[1]
		}
	}
	return ""
}

// extractIP returns the first syntactically valid IP address in a string.
func extractIP(s string) string {
	for _, match := range ipPattern.FindAllStringSubmatch(s, -1) {
		if net.ParseIP(match[1]) != nil {
			return match[1]
		}
	}
	return ""
}

// parseMediaTypeLoose parses a Content-Type value, retrying with the
// parameters stripped when the parameter list is malformed. A broken charset
// parameter should not hide the media type from the rules.
func parseMediaTypeLoose(v string) (string, map[string]string, error) {
	mediaType, params, err := mime.ParseMediaType(v)
	if err == nil {
		return mediaType, params, nil
	}
	if i := strings.Index(v, ";"); i > 0 {
		if mt, _, err2 := mime.ParseMediaType(v[:i]); err2 == nil {
			return mt, map[string]string{}, err
		}
	}
	return "", nil, err
}

// TruncateRunes shortens a string to at most n runes, appending an ellipsis
// when it was cut.
func TruncateRunes(s string, n int) string {
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	runes := []rune(s)
	return string(runes[:n]) + "..."
}
