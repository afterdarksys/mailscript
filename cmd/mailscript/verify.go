package main

import (
	"fmt"
	"os"

	"github.com/afterdarksys/mailscript/pkg/authverify"
	"github.com/afterdarksys/mailscript/pkg/dnsx"
	"github.com/afterdarksys/mailscript/pkg/rules"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Cryptographically verify SPF, DKIM, DMARC and DANE",
	Long: `Verify sender authentication from the message bytes and DNS.

Nothing here reads the Authentication-Results header. That header is written
by whichever host handled the message last, and a sender can forge one
claiming any result they like, so a filter that trusts it is trivially
bypassed. Every verdict below is recomputed locally.

SPF needs the connecting client address. Supply it with --client-ip; without
it SPF reports "none" rather than guessing.

DANE requires a DNSSEC-validating resolver. Point --dns-server at one, or the
TLSA records are reported as insecure and unusable.

Exit status is 0 when the message authenticates, 1 when it does not, so this
can gate a pipeline.

Examples:
  mailscript verify --eml=message.eml --client-ip=192.0.2.1
  mailscript verify --eml=message.eml --dane --dns-server=1.1.1.1:53
  cat message.eml | mailscript verify --json`,
	RunE: runVerify,
}

var (
	verifyEML      string
	verifyMailFrom string
	verifyAuthserv string
)

func init() {
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.Flags().StringVar(&verifyEML, "eml", "", "Message file to verify (default: stdin)")
	verifyCmd.Flags().StringVar(&verifyMailFrom, "mail-from", "",
		"SMTP envelope sender; defaults to Return-Path when present")
	verifyCmd.Flags().StringVar(&verifyAuthserv, "authserv-id", "mailscript",
		"authserv-id to use in the rendered Authentication-Results field")
	addRuntimeFlags(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
	raw, err := readMessageInput(verifyEML)
	if err != nil {
		return err
	}

	ctx, err := rules.ParseMessage(raw)
	if err != nil {
		return fmt.Errorf("parse message: %w", err)
	}

	// This command exists to verify, so DNS is always on.
	enableDNS = true
	rt, err := buildRuntime()
	if err != nil {
		return err
	}

	if clientIP != "" {
		ctx.SenderIP = clientIP
	}
	if heloName != "" {
		ctx.HELO = heloName
	}
	if verifyMailFrom != "" {
		ctx.EnvelopeFrom = verifyMailFrom
	}
	ctx.Resolver = rt.resolver
	ctx.TrustedAuthServs = trustedAuthServ

	result := ctx.VerifyAuth(checkDANE)

	if outputJSON {
		if err := printJSON(buildVerifyPayload(ctx, result)); err != nil {
			return err
		}
	} else {
		printVerifyReport(ctx, result)
	}

	if !result.Authenticated {
		// A non-zero status lets this gate a pipeline without parsing output.
		os.Exit(1)
	}
	return nil
}

func printVerifyReport(ctx *rules.MessageContext, result *authverify.Result) {
	fmt.Printf("From domain: %s\n", result.FromDomain)
	if ip := ctx.SenderIP; ip != "" {
		fmt.Printf("Client IP:   %s\n", ip)
	} else {
		fmt.Println("Client IP:   not supplied (SPF cannot be evaluated; pass --client-ip)")
	}

	fmt.Println("\nSPF")
	fmt.Printf("Result:    %s\n", result.SPF.Result)
	fmt.Printf("Identity:  %s\n", orNone(result.SPF.Domain))
	if result.SPF.Mechanism != "" {
		fmt.Printf("Matched:   %s\n", result.SPF.Mechanism)
	}
	fmt.Printf("Lookups:   %d\n", result.SPF.Lookups)
	if result.SPF.Explanation != "" {
		fmt.Printf("Detail:    %s\n", result.SPF.Explanation)
	}

	fmt.Println("\nDKIM")
	fmt.Printf("Result:    %s\n", result.DKIM.Result)
	if len(result.DKIM.Signatures) == 0 {
		fmt.Println("No signatures present.")
	}
	for i, sig := range result.DKIM.Signatures {
		fmt.Printf("Signature %d: %s\n", i+1, sig.Result)
		fmt.Printf("d=%s s=%s a=%s", orNone(sig.Domain), orNone(sig.Selector), orNone(sig.Algorithm))
		if sig.KeyBits > 0 {
			fmt.Printf("key=%d bits", sig.KeyBits)
		}
		fmt.Println()
		if len(sig.HeadersSigned) > 0 {
			fmt.Printf("signed headers: %v\n", sig.HeadersSigned)
		}
		fmt.Printf("%s\n", sig.Explanation)
	}

	fmt.Println("\nDMARC")
	fmt.Printf("Result:      %s\n", result.DMARC.Result)
	fmt.Printf("SPF aligned:  %t\n", result.DMARC.SPFAligned)
	fmt.Printf("DKIM aligned: %t\n", result.DMARC.DKIMAligned)
	if record := result.DMARC.Record; record != nil {
		fmt.Printf("Policy:      p=%s sp=%s pct=%d adkim=%s aspf=%s (from %s)\n",
			record.Policy, record.SubdomainPolicy, record.Percent,
			record.ADKIM, record.ASPF, record.Domain)
	}
	fmt.Printf("Detail:      %s\n", orNone(result.DMARC.Explanation))

	fmt.Println("\nARC")
	fmt.Printf("Result: %s\n", result.ARC.Result)
	fmt.Printf("Detail: %s\n", result.ARC.Explanation)
	for _, set := range result.ARC.Sets {
		fmt.Printf("i=%d d=%s s=%s cv=%s ams=%s seal=%s\n",
			set.Instance, set.Domain, set.Selector, set.ChainValidation, set.MessageSignature, set.Seal)
	}

	if result.DANE != nil {
		fmt.Println("\nDANE")
		fmt.Printf("Result: %s\n", result.DANE.Result)
		fmt.Printf("Detail: %s\n", result.DANE.Explanation)
		for _, host := range result.DANE.Hosts {
			fmt.Printf("%s: %s (dnssec=%t)\n", host.Host, host.Result, host.DNSSECValidated)
			for _, record := range host.Records {
				fmt.Printf("%s\n", authverify.DescribeTLSA(record))
			}
		}
	}

	if warnings := result.Warnings(); len(warnings) > 0 {
		fmt.Println("\nWarnings")
		for _, w := range warnings {
			fmt.Printf("- %s\n", w)
		}
	}

	// Show what the message itself claimed, and whether that claim is
	// trustworthy. A mismatch here is a strong forgery signal.
	reported := ctx.AuthResults()
	if reported.Present {
		fmt.Println("\nReported by upstream (not trusted unless the authserv-id is yours)")
		fmt.Printf("spf=%s dkim=%s dmarc=%s trusted=%t\n",
			orNone(reported.SPF), orNone(reported.DKIM), orNone(reported.DMARC), reported.Trusted)
		if !reported.Trusted && (reported.SPF == "pass" || reported.DKIM == "pass" || reported.DMARC == "pass") {
			fmt.Println("CAUTION: the message carries an untrusted Authentication-Results claiming a pass.")
		}
	}

	fmt.Printf("\nVerdict: %s\n", result.Summary())
	fmt.Printf("Disposition requested by policy: %s\n", result.Disposition())
	fmt.Printf("\nAuthentication-Results: %s\n", result.AuthenticationResults(verifyAuthserv))
}

func buildVerifyPayload(ctx *rules.MessageContext, result *authverify.Result) map[string]interface{} {
	signatures := make([]map[string]interface{}, 0, len(result.DKIM.Signatures))
	for _, sig := range result.DKIM.Signatures {
		signatures = append(signatures, map[string]interface{}{
			"result":         sig.Result,
			"domain":         sig.Domain,
			"selector":       sig.Selector,
			"algorithm":      sig.Algorithm,
			"key_bits":       sig.KeyBits,
			"body_truncated": sig.BodyTruncated,
			"expired":        sig.Expired,
			"explanation":    sig.Explanation,
		})
	}

	payload := map[string]interface{}{
		"authenticated": result.Authenticated,
		"disposition":   result.Disposition(),
		"from_domain":   result.FromDomain,
		"spf": map[string]interface{}{
			"result":      result.SPF.Result,
			"domain":      result.SPF.Domain,
			"mechanism":   result.SPF.Mechanism,
			"lookups":     result.SPF.Lookups,
			"explanation": result.SPF.Explanation,
		},
		"dkim": map[string]interface{}{
			"result":          result.DKIM.Result,
			"passing_domains": result.DKIM.PassingDomains,
			"signatures":      signatures,
		},
		"dmarc": map[string]interface{}{
			"result":       result.DMARC.Result,
			"spf_aligned":  result.DMARC.SPFAligned,
			"dkim_aligned": result.DMARC.DKIMAligned,
			"explanation":  result.DMARC.Explanation,
		},
		"arc": map[string]interface{}{
			"result":      result.ARC.Result,
			"sets":        result.ARC.Sets,
			"explanation": result.ARC.Explanation,
		},
		"warnings":               result.Warnings(),
		"authentication_results": result.AuthenticationResults(verifyAuthserv),
		"elapsed_ms":             result.Elapsed.Milliseconds(),
	}

	if record := result.DMARC.Record; record != nil {
		payload["dmarc"].(map[string]interface{})["policy"] = record.Policy
		payload["dmarc"].(map[string]interface{})["pct"] = record.Percent
	}

	if result.DANE != nil {
		hosts := make([]map[string]interface{}, 0, len(result.DANE.Hosts))
		for _, host := range result.DANE.Hosts {
			records := make([]string, 0, len(host.Records))
			for _, r := range host.Records {
				records = append(records, authverify.DescribeTLSA(r))
			}
			hosts = append(hosts, map[string]interface{}{
				"host":             host.Host,
				"result":           host.Result,
				"dnssec_validated": host.DNSSECValidated,
				"records":          records,
			})
		}
		payload["dane"] = map[string]interface{}{
			"result":       result.DANE.Result,
			"secure_hosts": result.DANE.SecureHosts,
			"hosts":        hosts,
		}
	}

	reported := ctx.AuthResults()
	payload["reported"] = map[string]interface{}{
		"present":             reported.Present,
		"trusted":             reported.Trusted,
		"spf":                 reported.SPF,
		"dkim":                reported.DKIM,
		"dmarc":               reported.DMARC,
		"untrusted_authservs": reported.UntrustedAuthServs,
	}

	return payload
}

// ensure the dnsx import is used even if the resolver construction moves.
var _ = dnsx.DefaultRBLs
