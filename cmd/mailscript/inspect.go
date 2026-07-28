package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/afterdarksys/mailscript/pkg/rules"
	"github.com/spf13/cobra"
)

var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Report everything MailScript can determine about a message",
	Long: `Parse a message and report header validation findings, sender
authentication, human-versus-automated classification, URLs, and attachments.

This runs no rule script. It is the tool for understanding why a rule fired,
or for triaging a suspicious message by hand.

Examples:
  # Offline analysis: headers, content, classification
  mailscript inspect --eml=message.eml

  # Include cryptographic verification of SPF, DKIM and DMARC
  mailscript inspect --eml=message.eml --verify --client-ip=192.0.2.1

  # Read from a pipe
  cat message.eml | mailscript inspect --json`,
	RunE: runInspect,
}

var (
	inspectEML      string
	inspectSeverity string
)

func init() {
	rootCmd.AddCommand(inspectCmd)
	inspectCmd.Flags().StringVar(&inspectEML, "eml", "", "Message file to inspect (default: stdin)")
	inspectCmd.Flags().StringVar(&inspectSeverity, "min-severity", "info",
		"Lowest validation severity to report: info, low, medium, high, critical")
	addRuntimeFlags(inspectCmd)
}

func runInspect(cmd *cobra.Command, args []string) error {
	raw, err := readMessageInput(inspectEML)
	if err != nil {
		return err
	}

	ctx, err := rules.ParseMessage(raw)
	if err != nil {
		return fmt.Errorf("parse message: %w", err)
	}

	rt, err := buildRuntime()
	if err != nil {
		return err
	}
	rt.apply(ctx)

	findings := filterFindings(ctx.ValidateHeaders(), inspectSeverity)
	assessment := ctx.AssessHuman()

	if outputJSON {
		return printJSON(buildInspectPayload(ctx, findings, assessment))
	}

	printInspectReport(ctx, findings, assessment)
	return nil
}

func readMessageInput(path string) ([]byte, error) {
	if path == "" || path == "-" {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		if len(raw) == 0 {
			return nil, fmt.Errorf("no message on stdin; pass --eml=<file>")
		}
		return raw, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read message: %w", err)
	}
	return raw, nil
}

func filterFindings(findings []rules.Finding, minSeverity string) []rules.Finding {
	ranks := map[string]int{"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
	threshold := ranks[strings.ToLower(minSeverity)]

	var out []rules.Finding
	for _, f := range findings {
		if ranks[f.Severity] >= threshold {
			out = append(out, f)
		}
	}
	return out
}

func printInspectReport(ctx *rules.MessageContext, findings []rules.Finding, assessment *rules.HumanAssessment) {
	section := func(title string) {
		fmt.Printf("\n%s\n%s\n", title, strings.Repeat("-", len(title)))
	}

	fmt.Println("MESSAGE")
	fmt.Println(strings.Repeat("=", 7))
	fmt.Printf("From:       %s\n", ctx.Get("From"))
	fmt.Printf("To:         %s\n", ctx.Get("To"))
	fmt.Printf("Subject:    %s\n", ctx.Get("Subject"))
	fmt.Printf("Date:       %s\n", ctx.Get("Date"))
	fmt.Printf("Message-ID: %s\n", ctx.Get("Message-ID"))
	fmt.Printf("Size:       %d bytes of headers, %d bytes of body\n", ctx.HeaderSize, ctx.BodySize)
	fmt.Printf("Hops:       %d Received fields\n", len(ctx.ReceivedChain()))

	section("SENDER CLASSIFICATION")
	fmt.Printf("Class:       %s\n", assessment.Class)
	fmt.Printf("Human score: %.0f / 100\n", assessment.Score)
	if verbose && len(assessment.Reasons) > 0 {
		fmt.Println("Signals:")
		for _, reason := range assessment.Reasons {
			fmt.Printf("%s\n", reason)
		}
	}

	section("AUTHENTICATION")
	if ctx.Verified != nil {
		result := ctx.Verified
		fmt.Printf("Verified:    %s\n", result.Summary())
		fmt.Printf("SPF:         %s (%s)\n", result.SPF.Result, orNone(result.SPF.Explanation))
		fmt.Printf("DKIM:        %s\n", result.DKIM.Result)
		for _, sig := range result.DKIM.Signatures {
			fmt.Printf("d=%s s=%s %s: %s\n", sig.Domain, sig.Selector, sig.Algorithm, sig.Explanation)
		}
		fmt.Printf("DMARC:       %s (%s)\n", result.DMARC.Result, orNone(result.DMARC.Explanation))
		fmt.Printf("Disposition: %s\n", result.Disposition())
		if result.DANE != nil {
			fmt.Printf("DANE:        %s (%s)\n", result.DANE.Result, result.DANE.Explanation)
		}
		for _, warning := range result.Warnings() {
			fmt.Printf("WARNING: %s\n", warning)
		}
	} else {
		reported := ctx.AuthResults()
		fmt.Println("Not verified. Pass --verify to check SPF, DKIM and DMARC cryptographically.")
		if reported.Present {
			fmt.Printf("Reported by upstream: spf=%s dkim=%s dmarc=%s\n",
				orNone(reported.SPF), orNone(reported.DKIM), orNone(reported.DMARC))
			if !reported.Trusted {
				fmt.Println("These values are UNTRUSTED: the header can be forged by the sender.")
				if len(reported.UntrustedAuthServs) > 0 {
					fmt.Printf("Claimed by: %s\n", strings.Join(reported.UntrustedAuthServs, ", "))
				}
			}
		}
	}

	section(fmt.Sprintf("HEADER VALIDATION (%d findings)", len(findings)))
	if len(findings) == 0 {
		fmt.Println("No findings.")
	}
	for _, f := range findings {
		fmt.Printf("[%-8s] %-32s %s\n", strings.ToUpper(f.Severity), f.Code, f.Message)
	}

	urls := ctx.URLs()
	section(fmt.Sprintf("CONTENT (%d URLs, %d attachments)", len(urls), len(ctx.Attachments)))
	fmt.Printf("Parts:            %d\n", len(ctx.Parts))
	fmt.Printf("Text part:        %t\n", strings.TrimSpace(ctx.TextBody) != "")
	fmt.Printf("HTML part:        %t\n", ctx.HTMLBody != "")
	fmt.Printf("Tracking pixels:  %d\n", ctx.TrackingPixelCount())

	if len(urls) > 0 {
		fmt.Println("URL hosts:")
		for _, host := range ctx.URLDomains() {
			fmt.Printf("%s\n", host)
		}
	}
	for _, mismatch := range ctx.URLDisplayMismatches() {
		fmt.Printf("LINK MISMATCH: text claims %s but href points to %s\n",
			mismatch.DisplayHost, mismatch.HrefHost)
	}
	for _, a := range ctx.Attachments {
		fmt.Printf("Attachment: %s (%s, %d bytes) sha256=%s\n",
			a.Filename, a.ContentType, a.Size, a.SHA256[:16])
	}
	for _, name := range ctx.DoubleExtensionAttachments() {
		fmt.Printf("DOUBLE EXTENSION: %s\n", name)
	}
	for _, name := range ctx.RTLOverrideAttachments() {
		fmt.Printf("BIDI OVERRIDE IN FILENAME: %s\n", name)
	}

	fmt.Println()
}

func buildInspectPayload(ctx *rules.MessageContext, findings []rules.Finding, assessment *rules.HumanAssessment) map[string]interface{} {
	findingList := make([]map[string]interface{}, 0, len(findings))
	for _, f := range findings {
		findingList = append(findingList, map[string]interface{}{
			"code":     f.Code,
			"severity": f.Severity,
			"header":   f.Header,
			"message":  f.Message,
			"score":    f.Score,
		})
	}

	attachments := make([]map[string]interface{}, 0, len(ctx.Attachments))
	for _, a := range ctx.Attachments {
		attachments = append(attachments, map[string]interface{}{
			"filename":     a.Filename,
			"content_type": a.ContentType,
			"size":         a.Size,
			"sha256":       a.SHA256,
		})
	}

	payload := map[string]interface{}{
		"from":    ctx.Get("From"),
		"to":      ctx.Get("To"),
		"subject": ctx.Get("Subject"),
		"classification": map[string]interface{}{
			"class":       assessment.Class,
			"human_score": assessment.Score,
			"reasons":     assessment.Reasons,
		},
		"validation": map[string]interface{}{
			"findings": findingList,
			"count":    len(findingList),
		},
		"content": map[string]interface{}{
			"urls":                   ctx.URLs(),
			"url_domains":            ctx.URLDomains(),
			"tracking_pixels":        ctx.TrackingPixelCount(),
			"attachments":            attachments,
			"double_extensions":      ctx.DoubleExtensionAttachments(),
			"url_display_mismatches": len(ctx.URLDisplayMismatches()),
		},
	}

	if ctx.Verified != nil {
		payload["authentication"] = authPayload(ctx)
	} else {
		reported := ctx.AuthResults()
		payload["authentication"] = map[string]interface{}{
			"verified":            false,
			"reported_spf":        reported.SPF,
			"reported_dkim":       reported.DKIM,
			"reported_dmarc":      reported.DMARC,
			"reported_trusted":    reported.Trusted,
			"untrusted_authservs": reported.UntrustedAuthServs,
		}
	}

	return payload
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "none"
	}
	return s
}
