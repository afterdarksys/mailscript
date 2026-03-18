package rules

import (
	"fmt"
	"regexp"

	"go.starlark.net/starlark"
)

// MessageContext holds the email headers and metadata accessible to Starlark
type MessageContext struct {
	Headers         map[string]string
	Body            string  // Email body content
	MimeType        string  // MIME type of the message
	SpamScore       float64 // Spam score (0.0 to 10.0)
	VirusStatus     string  // Virus scan status: "clean", "infected", "unknown"
	SenderDID       string
	Actions         []string            // List of actions taken by the script
	ModifiedHeaders map[string]string   // Headers added/modified by the script
	BodySize        int64               // Size of body in bytes
	HeaderSize      int64               // Size of headers in bytes
	EnvelopeSenders []string            // List of envelope senders
	ContentFilter      string              // Current content filter
	ContentFilterName  string              // Content filter name
	ContentFilterRules map[string]string   // Content filter rules
	Instance           string              // Current processing instance
	InstanceName       string              // Instance name
	LogEntries         []string            // Log entries created by script

	// DNS and Network Information
	SenderDomain       string              // Sender's domain
	SenderIP           string              // Sender's IP address
	DNSResolved        bool                // Whether DNS was resolved
	MXRecords          []string            // MX records for sender domain
	RBLListed          bool                // Whether sender is in RBL
	RBLName            string              // Name of RBL where listed
	ReceivedHeaders    []string            // Received headers in order
}

// executeEngine runs a Starlark source script against the message context
func ExecuteEngine(scriptSource string, msg *MessageContext) error {
	// Setup the Starlark environment (The "MailScript" standard lib)
	var getHeader = starlark.NewBuiltin("get_header", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var headerName string
		if err := starlark.UnpackArgs("get_header", args, kwargs, "name", &headerName); err != nil {
			return nil, err
		}
		
		val, ok := msg.Headers[headerName]
		if !ok {
			return starlark.String(""), nil
		}
		return starlark.String(val), nil
	})

	var discard = starlark.NewBuiltin("discard", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		msg.Actions = append(msg.Actions, "discard")
		return starlark.None, nil
	})

	var accept = starlark.NewBuiltin("accept", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		msg.Actions = append(msg.Actions, "accept")
		return starlark.None, nil
	})

	var fileinto = starlark.NewBuiltin("fileinto", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var folderName string
		if err := starlark.UnpackArgs("fileinto", args, kwargs, "folder", &folderName); err != nil {
			return nil, err
		}
		msg.Actions = append(msg.Actions, fmt.Sprintf("fileinto:%s", folderName))
		return starlark.None, nil
	})

	var regexMatch = starlark.NewBuiltin("regex_match", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var pattern, text string
		if err := starlark.UnpackArgs("regex_match", args, kwargs, "pattern", &pattern, "text", &text); err != nil {
			return nil, err
		}
		
		matched, _ := regexp.MatchString(pattern, text)
		return starlark.Bool(matched), nil
	})

	var getRecipientDID = starlark.NewBuiltin("get_recipient_did", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		// Just a placeholder to show MailScript compatibility
		return starlark.String(msg.SenderDID), nil
	})

	var autoReply = starlark.NewBuiltin("auto_reply", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var replyText string
		if err := starlark.UnpackArgs("auto_reply", args, kwargs, "text", &replyText); err != nil {
			return nil, err
		}
		msg.Actions = append(msg.Actions, fmt.Sprintf("auto_reply:%s", replyText))
		return starlark.None, nil
	})

	// New functions from what_we_need.md
	var searchBody = starlark.NewBuiltin("search_body", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var text string
		if err := starlark.UnpackArgs("search_body", args, kwargs, "text", &text); err != nil {
			return nil, err
		}
		matched := regexp.MustCompile(regexp.QuoteMeta(text)).MatchString(msg.Body)
		return starlark.Bool(matched), nil
	})

	var getMimeType = starlark.NewBuiltin("getmimetype", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		return starlark.String(msg.MimeType), nil
	})

	var getSpamScore = starlark.NewBuiltin("getspamscore", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		return starlark.Float(msg.SpamScore), nil
	})

	var getVirusStatus = starlark.NewBuiltin("getvirusstatus", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		return starlark.String(msg.VirusStatus), nil
	})

	var addHeader = starlark.NewBuiltin("add_header", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name, value string
		if err := starlark.UnpackArgs("add_header", args, kwargs, "name", &name, "value", &value); err != nil {
			return nil, err
		}
		if msg.ModifiedHeaders == nil {
			msg.ModifiedHeaders = make(map[string]string)
		}
		msg.ModifiedHeaders[name] = value
		msg.Actions = append(msg.Actions, fmt.Sprintf("add_header:%s:%s", name, value))
		return starlark.None, nil
	})

	var divertTo = starlark.NewBuiltin("divert_to", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var emailAddress string
		if err := starlark.UnpackArgs("divert_to", args, kwargs, "email_address", &emailAddress); err != nil {
			return nil, err
		}
		msg.Actions = append(msg.Actions, fmt.Sprintf("divert_to:%s", emailAddress))
		return starlark.None, nil
	})

	var screenTo = starlark.NewBuiltin("screen_to", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var emailAddress string
		if err := starlark.UnpackArgs("screen_to", args, kwargs, "email_address", &emailAddress); err != nil {
			return nil, err
		}
		msg.Actions = append(msg.Actions, fmt.Sprintf("screen_to:%s", emailAddress))
		return starlark.None, nil
	})

	var skipMalwareCheck = starlark.NewBuiltin("skip_malware_check", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var sender string
		if err := starlark.UnpackArgs("skip_malware_check", args, kwargs, "sender", &sender); err != nil {
			return nil, err
		}
		msg.Actions = append(msg.Actions, fmt.Sprintf("skip_malware_check:%s", sender))
		return starlark.None, nil
	})

	var skipSpamCheck = starlark.NewBuiltin("skip_spam_check", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var sender string
		if err := starlark.UnpackArgs("skip_spam_check", args, kwargs, "sender", &sender); err != nil {
			return nil, err
		}
		msg.Actions = append(msg.Actions, fmt.Sprintf("skip_spam_check:%s", sender))
		return starlark.None, nil
	})

	var skipWhitelistCheck = starlark.NewBuiltin("skip_whitelist_check", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var ip string
		if err := starlark.UnpackArgs("skip_whitelist_check", args, kwargs, "ip", &ip); err != nil {
			return nil, err
		}
		msg.Actions = append(msg.Actions, fmt.Sprintf("skip_whitelist_check:%s", ip))
		return starlark.None, nil
	})

	var forceSecondPass = starlark.NewBuiltin("force_second_pass", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var mailserver string
		if err := starlark.UnpackArgs("force_second_pass", args, kwargs, "mailserver", &mailserver); err != nil {
			return nil, err
		}
		msg.Actions = append(msg.Actions, fmt.Sprintf("force_second_pass:%s", mailserver))
		return starlark.None, nil
	})

	var setDLP = starlark.NewBuiltin("set_dlp", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var mode, target string
		if err := starlark.UnpackArgs("set_dlp", args, kwargs, "mode", &mode, "target", &target); err != nil {
			return nil, err
		}
		msg.Actions = append(msg.Actions, fmt.Sprintf("set_dlp:%s:%s", mode, target))
		return starlark.None, nil
	})

	var skipDLP = starlark.NewBuiltin("skip_dlp", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var mode, target string
		if err := starlark.UnpackArgs("skip_dlp", args, kwargs, "mode", &mode, "target", &target); err != nil {
			return nil, err
		}
		msg.Actions = append(msg.Actions, fmt.Sprintf("skip_dlp:%s:%s", mode, target))
		return starlark.None, nil
	})

	var quarantine = starlark.NewBuiltin("quarantine", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		msg.Actions = append(msg.Actions, "quarantine")
		return starlark.None, nil
	})

	var addToDigest = starlark.NewBuiltin("add_to_next_digest", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		msg.Actions = append(msg.Actions, "add_to_digest")
		return starlark.Bool(true), nil
	})

	// Additional functions
	var drop = starlark.NewBuiltin("drop", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		msg.Actions = append(msg.Actions, "drop")
		return starlark.None, nil
	})

	var bounce = starlark.NewBuiltin("bounce", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		msg.Actions = append(msg.Actions, "bounce")
		return starlark.None, nil
	})

	var replyWithSMTPError = starlark.NewBuiltin("reply_with_smtp_error", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var code int
		if err := starlark.UnpackArgs("reply_with_smtp_error", args, kwargs, "code", &code); err != nil {
			return nil, err
		}
		msg.Actions = append(msg.Actions, fmt.Sprintf("smtp_error:%d", code))
		return starlark.None, nil
	})

	var replyWithSMTPDSN = starlark.NewBuiltin("reply_with_smtp_dsn", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var dsn string
		if err := starlark.UnpackArgs("reply_with_smtp_dsn", args, kwargs, "dsn", &dsn); err != nil {
			return nil, err
		}
		msg.Actions = append(msg.Actions, fmt.Sprintf("smtp_dsn:%s", dsn))
		return starlark.None, nil
	})

	var logEntry = starlark.NewBuiltin("log_entry", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var message string
		if err := starlark.UnpackArgs("log_entry", args, kwargs, "message", &message); err != nil {
			return nil, err
		}
		if msg.LogEntries == nil {
			msg.LogEntries = make([]string, 0)
		}
		msg.LogEntries = append(msg.LogEntries, message)
		msg.Actions = append(msg.Actions, fmt.Sprintf("log:%s", message))
		return starlark.None, nil
	})

	var bodySize = starlark.NewBuiltin("body_size", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		return starlark.MakeInt64(msg.BodySize), nil
	})

	var headerSize = starlark.NewBuiltin("header_size", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		return starlark.MakeInt64(msg.HeaderSize), nil
	})

	var numEnvelope = starlark.NewBuiltin("num_envelope", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		return starlark.MakeInt(len(msg.EnvelopeSenders)), nil
	})

	var getContentFilter = starlark.NewBuiltin("get_content_filter", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		return starlark.String(msg.ContentFilter), nil
	})

	var getContentFilterName = starlark.NewBuiltin("get_content_filter_name", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		return starlark.String(msg.ContentFilterName), nil
	})

	var getContentFilterRules = starlark.NewBuiltin("get_content_filter_rules", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		// Convert map to Starlark dict
		dict := starlark.NewDict(len(msg.ContentFilterRules))
		for k, v := range msg.ContentFilterRules {
			dict.SetKey(starlark.String(k), starlark.String(v))
		}
		return dict, nil
	})

	var setContentFilterRules = starlark.NewBuiltin("set_content_filter_rules", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var rule string
		if err := starlark.UnpackArgs("set_content_filter_rules", args, kwargs, "rule", &rule); err != nil {
			return nil, err
		}
		msg.Actions = append(msg.Actions, fmt.Sprintf("set_filter_rules:%s", rule))
		return starlark.Bool(true), nil
	})

	var getInstance = starlark.NewBuiltin("get_instance", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		return starlark.String(msg.Instance), nil
	})

	var getInstanceName = starlark.NewBuiltin("get_instance_name", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		return starlark.String(msg.InstanceName), nil
	})

	// DNS and Network Functions
	var dnsCheck = starlark.NewBuiltin("dns_check", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var domain string
		if err := starlark.UnpackArgs("dns_check", args, kwargs, "domain", &domain); err != nil {
			return nil, err
		}
		// In actual implementation, perform DNS lookup
		// For now, return the cached resolution status
		return starlark.Bool(msg.DNSResolved), nil
	})

	var dnsResolution = starlark.NewBuiltin("dns_resolution", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var domain string
		if err := starlark.UnpackArgs("dns_resolution", args, kwargs, "domain", &domain); err != nil {
			return nil, err
		}
		// In actual implementation, resolve domain to IP
		return starlark.String(msg.SenderIP), nil
	})

	var rblCheck = starlark.NewBuiltin("rbl_check", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var ip string
		var rblServer string
		if err := starlark.UnpackArgs("rbl_check", args, kwargs, "ip", &ip, "rbl_server?", &rblServer); err != nil {
			return nil, err
		}
		// In actual implementation, check IP against RBL
		msg.Actions = append(msg.Actions, fmt.Sprintf("rbl_check:%s:%s", ip, rblServer))
		return starlark.Bool(msg.RBLListed), nil
	})

	var validMX = starlark.NewBuiltin("valid_mx", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var domain string
		if err := starlark.UnpackArgs("valid_mx", args, kwargs, "domain", &domain); err != nil {
			return nil, err
		}
		// In actual implementation, check if domain has valid MX records
		return starlark.Bool(len(msg.MXRecords) > 0), nil
	})

	var getMXRecords = starlark.NewBuiltin("get_mx_records", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var domain string
		if err := starlark.UnpackArgs("get_mx_records", args, kwargs, "domain", &domain); err != nil {
			return nil, err
		}
		// Convert MX records to Starlark list
		mxList := make([]starlark.Value, len(msg.MXRecords))
		for i, mx := range msg.MXRecords {
			mxList[i] = starlark.String(mx)
		}
		return starlark.NewList(mxList), nil
	})

	var mxInRBL = starlark.NewBuiltin("mx_in_rbl", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var domain string
		var rblServer string
		if err := starlark.UnpackArgs("mx_in_rbl", args, kwargs, "domain", &domain, "rbl_server?", &rblServer); err != nil {
			return nil, err
		}
		// In actual implementation, check if any MX record is in RBL
		msg.Actions = append(msg.Actions, fmt.Sprintf("mx_rbl_check:%s:%s", domain, rblServer))
		return starlark.Bool(false), nil
	})

	var isMXIPv4 = starlark.NewBuiltin("is_mx_ipv4", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var domain string
		if err := starlark.UnpackArgs("is_mx_ipv4", args, kwargs, "domain", &domain); err != nil {
			return nil, err
		}
		// In actual implementation, check if domain has IPv4 MX records
		// For now, return true if we have any MX records
		return starlark.Bool(len(msg.MXRecords) > 0), nil
	})

	var isMXIPv6 = starlark.NewBuiltin("is_mx_ipv6", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var domain string
		if err := starlark.UnpackArgs("is_mx_ipv6", args, kwargs, "domain", &domain); err != nil {
			return nil, err
		}
		// In actual implementation, check if domain has IPv6 MX records
		return starlark.Bool(false), nil
	})

	var domainResolution = starlark.NewBuiltin("domain_resolution", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var sender string
		var verify bool
		if err := starlark.UnpackArgs("domain_resolution", args, kwargs, "sender", &sender, "verify", &verify); err != nil {
			return nil, err
		}
		// In actual implementation, resolve sender domain and optionally verify
		msg.Actions = append(msg.Actions, fmt.Sprintf("domain_resolve:%s:%t", sender, verify))
		return starlark.Bool(msg.DNSResolved), nil
	})

	var checkReceivedHeader = starlark.NewBuiltin("check_received_header", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var level int
		if err := starlark.UnpackArgs("check_received_header", args, kwargs, "level", &level); err != nil {
			return nil, err
		}
		// Get Received header at specified level (0-based from top)
		if level >= 0 && level < len(msg.ReceivedHeaders) {
			return starlark.String(msg.ReceivedHeaders[level]), nil
		}
		return starlark.String(""), nil
	})

	var getReceivedHeaders = starlark.NewBuiltin("get_received_headers", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		// Return all Received headers as a list
		headers := make([]starlark.Value, len(msg.ReceivedHeaders))
		for i, hdr := range msg.ReceivedHeaders {
			headers[i] = starlark.String(hdr)
		}
		return starlark.NewList(headers), nil
	})

	var getSenderIP = starlark.NewBuiltin("get_sender_ip", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		return starlark.String(msg.SenderIP), nil
	})

	var getSenderDomain = starlark.NewBuiltin("get_sender_domain", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		return starlark.String(msg.SenderDomain), nil
	})

	var getRBLStatus = starlark.NewBuiltin("get_rbl_status", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		// Return dictionary with RBL status
		dict := starlark.NewDict(2)
		dict.SetKey(starlark.String("listed"), starlark.Bool(msg.RBLListed))
		dict.SetKey(starlark.String("rbl_name"), starlark.String(msg.RBLName))
		return dict, nil
	})

	predeclared := starlark.StringDict{
		"get_header":              getHeader,
		"discard":                 discard,
		"accept":                  accept,
		"fileinto":                fileinto,
		"regex_match":             regexMatch,
		"get_recipient_did":       getRecipientDID,
		"auto_reply":              autoReply,
		"search_body":             searchBody,
		"getmimetype":             getMimeType,
		"getspamscore":            getSpamScore,
		"getvirusstatus":          getVirusStatus,
		"add_header":              addHeader,
		"divert_to":               divertTo,
		"screen_to":               screenTo,
		"skip_malware_check":      skipMalwareCheck,
		"skip_spam_check":         skipSpamCheck,
		"skip_whitelist_check":    skipWhitelistCheck,
		"force_second_pass":       forceSecondPass,
		"set_dlp":                 setDLP,
		"skip_dlp":                skipDLP,
		"quarantine":              quarantine,
		"add_to_next_digest":      addToDigest,
		"drop":                    drop,
		"bounce":                  bounce,
		"reply_with_smtp_error":   replyWithSMTPError,
		"reply_with_smtp_dsn":     replyWithSMTPDSN,
		"log_entry":               logEntry,
		"body_size":               bodySize,
		"header_size":             headerSize,
		"num_envelope":            numEnvelope,
		"get_content_filter":      getContentFilter,
		"get_content_filter_name": getContentFilterName,
		"get_content_filter_rules": getContentFilterRules,
		"set_content_filter_rules": setContentFilterRules,
		"get_instance":             getInstance,
		"get_instance_name":        getInstanceName,
		"dns_check":                dnsCheck,
		"dns_resolution":           dnsResolution,
		"rbl_check":                rblCheck,
		"valid_mx":                 validMX,
		"get_mx_records":           getMXRecords,
		"mx_in_rbl":                mxInRBL,
		"is_mx_ipv4":               isMXIPv4,
		"is_mx_ipv6":               isMXIPv6,
		"domain_resolution":        domainResolution,
		"check_received_header":    checkReceivedHeader,
		"get_received_headers":     getReceivedHeaders,
		"get_sender_ip":            getSenderIP,
		"get_sender_domain":        getSenderDomain,
		"get_rbl_status":           getRBLStatus,
	}

	thread := &starlark.Thread{Name: "MailScriptEngine"}

	// Execute the block
	globals, err := starlark.ExecFile(thread, "script.star", scriptSource, predeclared)
	if err != nil {
		return fmt.Errorf("starlark execution failed: %w", err)
	}

	// Sieve -> Mailscript requires calling an entrypoint if defined.
	// We'll mimic the legacy by calling 'evaluate()' if it exists.
	evalFunc, ok := globals["evaluate"]
	if ok {
		_, err := starlark.Call(thread, evalFunc, nil, nil)
		if err != nil {
			return fmt.Errorf("failed calling evaluate(): %w", err)
		}
	} else {
		// If evaluate isn't defined, we just assume the root level script did the work.
		if len(msg.Actions) == 0 {
			msg.Actions = append(msg.Actions, "accept")
		}
	}

	return nil
}
